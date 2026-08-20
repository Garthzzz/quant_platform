from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.workflow import canonical_json

from .database import evidence_connection
from .ids import normalize_identifier, stable_evidence_id
from .repository import EvidenceConflict, EvidenceRepository
from .resources import EvidenceResourceStore


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SCHEMA_VERSION = "qrh-reviewed-evidence-expansion/v1"


class CanonicalizationConflict(EvidenceConflict):
    """The reviewed command conflicts with immutable or already-applied material."""


class CanonicalizationEligibilityError(ValueError):
    """The reviewed command has not crossed an identity/rights evidence boundary."""


class ReviewedAuthor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=500)
    affiliations: tuple[str, ...] = ()
    name_form: Literal["full", "abbreviated", "unknown"] = "full"
    fact_origin: Literal[
        "official_external", "archive_local", "human_reconciled"
    ] = "official_external"


class ReviewedInstitutionResolution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["verified", "unresolved"]
    institutions: tuple[str, ...] = ()
    reason_code: str = Field(min_length=1, max_length=200)
    reason_text: str = Field(min_length=1, max_length=2_000)
    checked_source_fields: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        if self.status == "verified" and not self.institutions:
            raise ValueError("verified institution resolution requires institutions")
        if self.status == "unresolved" and self.institutions:
            raise ValueError("unresolved institution resolution cannot claim institutions")
        return self


class ReviewedExternalLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["landing", "doi", "repository", "publisher_pdf", "code", "data"]
    url: str = Field(pattern=r"^https://", max_length=4_000)
    verification_status: Literal["verified", "claimed"] = "verified"


class ReviewedVenueClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str = Field(min_length=1, max_length=1_000)
    volume: str | None = Field(default=None, max_length=100)
    issue: str | None = Field(default=None, max_length=100)
    pages: str | None = Field(default=None, max_length=200)
    fact_origin: Literal[
        "official_external", "archive_local", "human_reconciled"
    ]
    local_venue_stated: bool
    provenance_urn: str = Field(min_length=3, max_length=2_000)


class ReviewedSourceCategory(BaseModel):
    """A source-taxonomy fact; never a user-facing broad-class guess."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=500)
    display_name: str = Field(min_length=1, max_length=1_000)
    is_primary: bool = False
    fact_origin: Literal[
        "official_external", "archive_local", "human_reconciled"
    ]


class ReviewedCategoryAssertion(BaseModel):
    """Binds source categories to the deterministic display taxonomy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_system: Literal["arxiv", "crossref", "reviewed"]
    source_categories: tuple[ReviewedSourceCategory, ...] = Field(min_length=1)
    primary_source_category: str = Field(min_length=1, max_length=500)
    mapping_policy_version: str = Field(min_length=1, max_length=300)
    primary_mapped_category: str = Field(min_length=1, max_length=500)
    assertion_status: Literal["verified_external", "human_reviewed"]
    provenance_urn: str = Field(min_length=3, max_length=2_000)

    @model_validator(mode="after")
    def validate_primary_source(self) -> Self:
        matching = [
            item
            for item in self.source_categories
            if item.code == self.primary_source_category
        ]
        if len(matching) != 1:
            raise ValueError(
                "primary source category must identify exactly one source category"
            )
        declared_primary = [item for item in self.source_categories if item.is_primary]
        if len(declared_primary) != 1 or declared_primary[0].code != self.primary_source_category:
            raise ValueError("source category assertion requires exactly one matching primary")
        return self


class ReviewedMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(min_length=1, max_length=2_000)
    publication_date: str | None = Field(default=None, max_length=100)
    authors: tuple[ReviewedAuthor, ...] = ()
    author_resolution: Literal[
        "verified_full_external",
        "verified_abbreviated_local",
        "human_reconciled",
        "unresolved",
    ]
    venue: ReviewedVenueClaim | None = None
    categories: tuple[str, ...] = Field(min_length=1)
    category_fact_origin: Literal[
        "official_external", "archive_local", "deterministic_mapping",
        "model_classification", "human_reconciled"
    ]
    category_assertion: ReviewedCategoryAssertion
    institutions: ReviewedInstitutionResolution
    external_links: tuple[ReviewedExternalLink, ...] = Field(min_length=1)
    source_kind: Literal["publisher", "repository", "registry", "manual_review"]
    review_tier: Literal[
        "strict_four_field",
        "accepted_abbreviated_author",
        "accepted_local_venue_unstated",
        "accepted_explicit_local_identifier",
        "official_repository_full_material",
        "human_reconciled",
    ]
    assertion_boundaries: dict[str, object] = Field(default_factory=dict)
    provenance_urn: str = Field(min_length=3, max_length=2_000)

    @model_validator(mode="after")
    def validate_author_resolution(self) -> Self:
        if self.author_resolution == "unresolved" and self.authors:
            raise ValueError("unresolved author status cannot claim authors")
        if self.author_resolution != "unresolved" and not self.authors:
            raise ValueError("resolved author status requires reviewed authors")
        if self.category_assertion.primary_mapped_category not in self.categories:
            raise ValueError("primary mapped category must be present in display categories")
        return self


class ReviewedExcerpt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1)
    page_sha256: Sha256
    locator: dict[str, object] = Field(default_factory=dict)
    provenance_urn: str = Field(min_length=3, max_length=2_000)


class ReviewedFulltextLocator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    page_number: int = Field(ge=1)
    page_text_sha256: Sha256
    support_text_sha256: Sha256
    locator: dict[str, object] = Field(default_factory=dict)


class ReviewedReadingConclusion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1)
    source_locator: ReviewedFulltextLocator


class ReviewedReadingResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    worker_kind: Literal["codex", "human", "external"]
    analysis: str = Field(min_length=1)
    core_conclusions: tuple[ReviewedReadingConclusion, ...]
    fact_boundary: dict[str, object]
    provenance_urn: str = Field(min_length=3, max_length=2_000)


class ReviewedResource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(min_length=1, max_length=200)
    acquisition_case_id: str = Field(min_length=1, max_length=200)
    reading_result: ReviewedReadingResult | None = None


class ReviewedConclusion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1)
    evidence_scope: Literal["official_abstract", "fulltext_reading"]
    source_locator: ReviewedFulltextLocator | None = None
    provenance_urn: str = Field(min_length=3, max_length=2_000)

    @model_validator(mode="after")
    def validate_locator_scope(self) -> Self:
        if self.evidence_scope == "fulltext_reading" and self.source_locator is None:
            raise ValueError("full-text conclusion requires a page/text-hash locator")
        if self.evidence_scope == "official_abstract" and self.source_locator is not None:
            raise ValueError("official abstract conclusion uses the abstract excerpt locator")
        return self


class ReviewedCanonicalizationItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    item_key: str = Field(min_length=1, max_length=300)
    treatment: Literal["formal_citation", "associated_method_origin"]
    source_candidate_id: str = Field(min_length=1, max_length=128)
    paper_source_candidate_id: str = Field(min_length=1, max_length=128)
    resolution_case_id: str = Field(min_length=1, max_length=200)
    identity_decision_id: str = Field(min_length=1, max_length=200)
    metadata: ReviewedMetadata
    official_abstract_excerpt: ReviewedExcerpt | None = None
    resource: ReviewedResource | None = None
    core_conclusions: tuple[ReviewedConclusion, ...] = ()
    association_rationale: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def validate_treatment_and_evidence(self) -> Self:
        if self.treatment == "formal_citation":
            if self.source_candidate_id != self.paper_source_candidate_id:
                raise ValueError("formal citation must canonicalize its own source candidate")
            if self.association_rationale is not None:
                raise ValueError("formal citation cannot carry method-origin rationale")
        else:
            if self.source_candidate_id == self.paper_source_candidate_id:
                raise ValueError("method-origin association requires a distinct paper candidate")
            if not self.association_rationale:
                raise ValueError("method-origin association requires an explicit rationale")
        if self.resource is not None and self.official_abstract_excerpt is None:
            raise ValueError(
                "verified local resource reading requires independent official abstract evidence"
            )
        abstract = (
            self.official_abstract_excerpt.text
            if self.official_abstract_excerpt is not None
            else None
        )
        fulltext = (
            {
                (value.text, canonical_json(value.source_locator.model_dump(mode="json")))
                for value in self.resource.reading_result.core_conclusions
            }
            if self.resource is not None and self.resource.reading_result is not None
            else set()
        )
        for conclusion in self.core_conclusions:
            if conclusion.evidence_scope == "official_abstract":
                if abstract is None or conclusion.text != abstract:
                    raise ValueError(
                        "official-abstract conclusion must be the reviewed verbatim abstract"
                    )
                continue
            if self.resource is None:
                raise ValueError(
                    "full-text conclusion requires a verified local resource"
                )
            locator_json = (
                canonical_json(conclusion.source_locator.model_dump(mode="json"))
                if conclusion.source_locator is not None
                else ""
            )
            if (conclusion.text, locator_json) not in fulltext:
                raise ValueError(
                    "full-text conclusion must be present in the reviewed reading result"
                )
        return self


class ReviewedCanonicalizationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[SCHEMA_VERSION]
    review_id: str = Field(min_length=1, max_length=300)
    reviewed_by: str = Field(min_length=1, max_length=300)
    reviewed_at: str = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(min_length=1, max_length=300)
    provenance_urn: str = Field(min_length=3, max_length=2_000)
    items: tuple[ReviewedCanonicalizationItem, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_items(self) -> Self:
        keys = [item.item_key for item in self.items]
        if len(keys) != len(set(keys)):
            raise ValueError("reviewed canonicalization item keys must be unique")
        return self


class MethodOriginCandidateInput(BaseModel):
    """A reviewed request to create a paper entity beside a non-paper method clue."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_source_candidate_id: str = Field(min_length=1, max_length=128)
    derived_source_candidate_id: str | None = Field(default=None, min_length=1, max_length=128)
    identifier_scheme: Literal["doi", "arxiv", "pmid", "pmcid", "report", "isbn", "url"]
    identifier_value: str = Field(min_length=1, max_length=2_000)
    paper_title_claim: str = Field(min_length=1, max_length=2_000)
    publication_year: int | None = Field(default=None, ge=1400, le=3000)
    rationale: str = Field(min_length=1, max_length=2_000)
    provenance_urn: str = Field(min_length=3, max_length=2_000)

    @property
    def normalized_identifier(self) -> str:
        return normalize_identifier(self.identifier_scheme, self.identifier_value)

    @property
    def resolved_derived_source_candidate_id(self) -> str:
        if self.derived_source_candidate_id is not None:
            return self.derived_source_candidate_id
        suffix = hashlib.sha256(
            f"{self.identifier_scheme}:{self.normalized_identifier}".encode("utf-8")
        ).hexdigest()[:16]
        value = f"{self.original_source_candidate_id}__origin_paper_{suffix}"
        if len(value) > 128:
            value = f"origin_paper_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:32]}"
        return value


@dataclass(frozen=True, slots=True)
class CanonicalizationPlanItem:
    item_key: str
    treatment: str
    source_candidate_id: str
    paper_source_candidate_id: str
    identifier_scheme: str
    normalized_identifier: str
    paper_id: str
    official_abstract_mode: str
    resource_mode: str
    ledger_entry_count: int
    replay: bool


@dataclass(frozen=True, slots=True)
class CanonicalizationPlan:
    manifest_sha256: str
    items: tuple[CanonicalizationPlanItem, ...]


@dataclass(frozen=True, slots=True)
class CanonicalizationItemResult:
    receipt_id: str
    item_key: str
    paper_id: str
    treatment: str
    resource_mode: str
    bound_citations: int
    associated_relations: int
    created: bool


@dataclass(frozen=True, slots=True)
class CanonicalizationApplyResult:
    manifest_sha256: str
    items: tuple[CanonicalizationItemResult, ...]


@dataclass(frozen=True, slots=True)
class MethodOriginCandidateResult:
    derivation_id: str
    original_source_candidate_id: str
    derived_source_candidate_id: str
    derived_candidate_id: str
    identifier_scheme: str
    normalized_identifier: str
    created: bool


def load_reviewed_manifest(path: Path) -> ReviewedCanonicalizationManifest:
    return ReviewedCanonicalizationManifest.model_validate_json(
        path.read_text(encoding="utf-8")
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _row_material(row: sqlite3.Row, names: tuple[str, ...]) -> tuple[object, ...]:
    return tuple(row[name] for name in names)


class ReviewedEvidenceCanonicalizationService:
    """Apply an explicitly reviewed identity/material package in one DB transaction.

    The service deliberately does not mutate 0004 provider observations or identity
    decisions.  Those records are prerequisites; 0005 receipts are the only audit
    records claiming a canonicalization effect.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.repository = EvidenceRepository(settings)
        self.resource_store = EvidenceResourceStore(settings)

    def prepare_method_origin_candidates(
        self, inputs: tuple[MethodOriginCandidateInput, ...]
    ) -> tuple[MethodOriginCandidateResult, ...]:
        """Create separate paper candidates before opening expansion cases.

        The original method candidate remains immutable and rejected_non_paper.  The
        returned candidate IDs are the only valid subjects for subsequent provider
        resolution/identity decisions used by associated_method_origin items.
        """

        if not inputs:
            raise ValueError("method-origin derivation input is empty")
        self.repository.initialize()
        results: list[MethodOriginCandidateResult] = []
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            for value in inputs:
                original = connection.execute(
                    """
                    SELECT clue.clue_id,candidate.candidate_id
                    FROM paper_clue AS clue
                    JOIN paper_clue_candidate AS link USING(clue_id)
                    JOIN paper_candidate AS candidate USING(candidate_id)
                    WHERE clue.source_candidate_id=?
                      AND clue.entity_kind='method_or_resource_family'
                      AND clue.resolution_status='rejected_non_paper'
                      AND candidate.candidate_kind='non_paper_resource'
                      AND candidate.resolution_status='rejected_non_paper'
                    ORDER BY candidate.candidate_id LIMIT 1
                    """,
                    (value.original_source_candidate_id,),
                ).fetchone()
                if original is None:
                    raise CanonicalizationEligibilityError(
                        f"{value.original_source_candidate_id}: original method candidate is not rejected_non_paper"
                    )
                source_id = value.resolved_derived_source_candidate_id
                clue_id = stable_evidence_id("clue", "archive-ledger/v1", source_id)
                candidate_id = stable_evidence_id(
                    "pcand", "archive-resolution/v1", source_id, value.provenance_urn
                )
                now = utc_now()
                clue_expected = (
                    source_id,
                    "paper_or_scholarly_work",
                    None,
                    canonical_json(
                        {
                            "title": value.paper_title_claim,
                            "identifier_scheme": value.identifier_scheme,
                            "identifier_value": value.normalized_identifier,
                            "derived_from_method_candidate": value.original_source_candidate_id,
                        }
                    ),
                    value.provenance_urn,
                    "resolution_pending",
                )
                self._insert_exact(
                    connection,
                    table="paper_clue",
                    key_name="clue_id",
                    key=clue_id,
                    fields=(
                        "source_candidate_id", "entity_kind", "domain_category",
                        "raw_claim_json", "provenance_urn", "resolution_status",
                    ),
                    expected=clue_expected,
                    sql="""
                        INSERT INTO paper_clue(
                            clue_id,source_candidate_id,entity_kind,domain_category,
                            raw_claim_json,provenance_urn,resolution_status,created_at
                        ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    parameters=(clue_id, *clue_expected, now),
                    conflict_message="derived method-origin paper clue conflicts",
                )
                candidate_expected = (
                    "paper", value.paper_title_claim, value.publication_year,
                    "proposed", value.provenance_urn,
                )
                self._insert_exact(
                    connection,
                    table="paper_candidate",
                    key_name="candidate_id",
                    key=candidate_id,
                    fields=(
                        "candidate_kind", "title_claim", "publication_year",
                        "resolution_status", "provenance_urn",
                    ),
                    expected=candidate_expected,
                    sql="""
                        INSERT INTO paper_candidate(
                            candidate_id,candidate_kind,title_claim,publication_year,
                            resolution_status,provenance_urn,created_at
                        ) VALUES(?,?,?,?,?,?,?)
                    """,
                    parameters=(candidate_id, *candidate_expected, now),
                    conflict_message="derived method-origin paper candidate conflicts",
                )
                link_evidence = canonical_json(
                    {
                        "derivation": "associated_method_origin",
                        "original_source_candidate_id": value.original_source_candidate_id,
                        "strong_identifier_claim": {
                            "scheme": value.identifier_scheme,
                            "normalized_value": value.normalized_identifier,
                        },
                    }
                )
                link = connection.execute(
                    """
                    SELECT evidence_json FROM paper_clue_candidate
                    WHERE clue_id=? AND candidate_id=? AND link_kind='local_claim'
                    """,
                    (clue_id, candidate_id),
                ).fetchone()
                if link is None:
                    connection.execute(
                        """
                        INSERT INTO paper_clue_candidate(
                            clue_id,candidate_id,link_kind,evidence_json,linked_at
                        ) VALUES(?,?,'local_claim',?,?)
                        """,
                        (clue_id, candidate_id, link_evidence, now),
                    )
                elif link["evidence_json"] != link_evidence:
                    raise CanonicalizationConflict("derived clue/candidate link conflicts")
                derivation_id = stable_evidence_id(
                    "originderive",
                    value.original_source_candidate_id,
                    value.identifier_scheme,
                    value.normalized_identifier,
                )
                expected = (
                    value.original_source_candidate_id,
                    source_id,
                    candidate_id,
                    value.identifier_scheme,
                    value.normalized_identifier,
                    value.rationale,
                    value.provenance_urn,
                )
                created = self._insert_exact(
                    connection,
                    table="evidence_method_origin_candidate_derivation",
                    key_name="derivation_id",
                    key=derivation_id,
                    fields=(
                        "original_source_candidate_id", "derived_source_candidate_id",
                        "derived_candidate_id", "identifier_scheme", "normalized_identifier",
                        "rationale", "provenance_urn",
                    ),
                    expected=expected,
                    sql="""
                        INSERT INTO evidence_method_origin_candidate_derivation(
                            derivation_id,original_source_candidate_id,
                            derived_source_candidate_id,derived_candidate_id,
                            identifier_scheme,normalized_identifier,rationale,
                            provenance_urn,created_at
                        ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    parameters=(derivation_id, *expected, now),
                    conflict_message="method-origin paper derivation conflicts",
                )
                results.append(
                    MethodOriginCandidateResult(
                        derivation_id,
                        value.original_source_candidate_id,
                        source_id,
                        candidate_id,
                        value.identifier_scheme,
                        value.normalized_identifier,
                        created,
                    )
                )
        return tuple(results)

    @staticmethod
    def static_plan(manifest: ReviewedCanonicalizationManifest) -> dict[str, object]:
        payload = manifest.model_dump(mode="json")
        return {
            "schema_version": manifest.schema_version,
            "manifest_sha256": _sha256_json(payload),
            "review_id": manifest.review_id,
            "idempotency_key": manifest.idempotency_key,
            "item_count": len(manifest.items),
            "items": [
                {
                    "item_key": item.item_key,
                    "treatment": item.treatment,
                    "source_candidate_id": item.source_candidate_id,
                    "paper_source_candidate_id": item.paper_source_candidate_id,
                    "resolution_case_id": item.resolution_case_id,
                    "identity_decision_id": item.identity_decision_id,
                    "official_abstract_mode": (
                        "verified_source_excerpt"
                        if item.official_abstract_excerpt is not None
                        else "none"
                    ),
                    "resource_mode": (
                        "verified_local_resource" if item.resource else "metadata_only"
                    ),
                    "core_conclusion_count": len(item.core_conclusions),
                }
                for item in manifest.items
            ],
        }

    @staticmethod
    def _decision_material(
        connection: sqlite3.Connection, item: ReviewedCanonicalizationItem
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT resolution.candidate_id,state.state,
                   decision.identity_decision_id,decision.decision_kind,
                   decision.identifier_scheme,decision.normalized_identifier,
                   decision.provider_observation_id
            FROM evidence_resolution_case AS resolution
            JOIN evidence_resolution_state AS state USING(resolution_case_id)
            JOIN evidence_identity_decision AS decision USING(resolution_case_id)
            WHERE resolution.resolution_case_id=?
              AND decision.identity_decision_id=?
            """,
            (item.resolution_case_id, item.identity_decision_id),
        ).fetchone()
        if row is None:
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: reviewed identity decision does not exist for its case"
            )
        if row["state"] != "identifier_verified" or row["decision_kind"] != "accept_verified_identifier":
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: resolution case has not reached identifier_verified"
            )
        if not row["identifier_scheme"] or not row["normalized_identifier"]:
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: accepted identity decision lacks a strong identifier"
            )
        normalized = normalize_identifier(
            str(row["identifier_scheme"]), str(row["normalized_identifier"])
        )
        if normalized != row["normalized_identifier"]:
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: decision identifier is not canonical"
            )
        linked = connection.execute(
            """
            SELECT 1
            FROM paper_clue_candidate AS link
            JOIN paper_clue AS clue USING(clue_id)
            WHERE link.candidate_id=? AND clue.source_candidate_id=?
            """,
            (row["candidate_id"], item.paper_source_candidate_id),
        ).fetchone()
        if linked is None:
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: resolution case belongs to another paper source candidate"
            )
        return row

    @staticmethod
    def _ledger_rows(
        connection: sqlite3.Connection, source_candidate_id: str
    ) -> list[sqlite3.Row]:
        return connection.execute(
            """
            SELECT ledger.ledger_entry_id,ledger.research_urn,
                   ledger.document_version_urn,ledger.citation_id,
                   occurrence.occurrence_kind
            FROM citation_ledger_entry AS ledger
            JOIN citation_occurrence AS occurrence USING(citation_id)
            JOIN paper_clue AS clue ON clue.clue_id=ledger.clue_id
            WHERE clue.source_candidate_id=?
            ORDER BY ledger.ledger_entry_id
            """,
            (source_candidate_id,),
        ).fetchall()

    @staticmethod
    def _paper_id_for_identifier(
        connection: sqlite3.Connection, scheme: str, normalized: str
    ) -> tuple[str, bool]:
        assigned = connection.execute(
            """
            SELECT paper_id FROM identifier_assignment_projection
            WHERE scheme=? AND normalized_value=?
            """,
            (scheme, normalized),
        ).fetchone()
        if assigned is not None:
            return str(assigned["paper_id"]), False
        identity_key = f"{scheme}:{normalized}"
        return stable_evidence_id("paper", "canonical-paper/v1", identity_key), True

    @staticmethod
    def _receipt_id(manifest: ReviewedCanonicalizationManifest, item_key: str) -> str:
        return stable_evidence_id(
            "canonreceipt", manifest.idempotency_key, item_key
        )

    @staticmethod
    def _result_material_sha256(
        *,
        item_material_sha256: str,
        paper_id: str,
        identifier_scheme: str,
        normalized_identifier: str,
        ledger_entry_ids: list[str],
        resource_id: str | None,
        official_abstract_excerpt_id: str | None,
        official_abstract_sha256: str | None,
    ) -> str:
        material: dict[str, object] = {
            "item_material_sha256": item_material_sha256,
            "paper_id": paper_id,
            "identifier": {
                "scheme": identifier_scheme,
                "normalized": normalized_identifier,
            },
            "ledger_entry_ids": ledger_entry_ids,
            "resource_id": resource_id,
        }
        if official_abstract_excerpt_id is not None:
            material["official_abstract_excerpt_id"] = official_abstract_excerpt_id
            material["official_abstract_sha256"] = official_abstract_sha256
        return _sha256_json(material)

    def plan(self, manifest: ReviewedCanonicalizationManifest) -> CanonicalizationPlan:
        self.repository.initialize()
        manifest_hash = _sha256_json(manifest.model_dump(mode="json"))
        plans: list[CanonicalizationPlanItem] = []
        with evidence_connection(self.settings) as connection:
            for item in manifest.items:
                decision = self._decision_material(connection, item)
                scheme = str(decision["identifier_scheme"])
                normalized = str(decision["normalized_identifier"])
                paper_id, _ = self._paper_id_for_identifier(connection, scheme, normalized)
                receipt_id = self._receipt_id(manifest, item.item_key)
                receipt = connection.execute(
                    "SELECT item_material_sha256 FROM evidence_canonicalization_receipt WHERE canonicalization_receipt_id=?",
                    (receipt_id,),
                ).fetchone()
                item_hash = _sha256_json(item.model_dump(mode="json"))
                if receipt is not None and receipt["item_material_sha256"] != item_hash:
                    raise CanonicalizationConflict(
                        f"{item.item_key}: idempotency key is bound to different reviewed material"
                    )
                plans.append(
                    CanonicalizationPlanItem(
                        item_key=item.item_key,
                        treatment=item.treatment,
                        source_candidate_id=item.source_candidate_id,
                        paper_source_candidate_id=item.paper_source_candidate_id,
                        identifier_scheme=scheme,
                        normalized_identifier=normalized,
                        paper_id=paper_id,
                        official_abstract_mode=(
                            "verified_source_excerpt"
                            if item.official_abstract_excerpt is not None
                            else "none"
                        ),
                        resource_mode=(
                            "verified_local_resource" if item.resource else "metadata_only"
                        ),
                        ledger_entry_count=len(
                            self._ledger_rows(connection, item.source_candidate_id)
                        ),
                        replay=receipt is not None,
                    )
                )
        return CanonicalizationPlan(manifest_hash, tuple(plans))

    @staticmethod
    def _insert_exact(
        connection: sqlite3.Connection,
        *,
        table: str,
        key_name: str,
        key: str,
        fields: tuple[str, ...],
        expected: tuple[object, ...],
        sql: str,
        parameters: tuple[object, ...],
        conflict_message: str,
    ) -> bool:
        row = connection.execute(
            f"SELECT * FROM {table} WHERE {key_name}=?", (key,)
        ).fetchone()
        if row is not None:
            if _row_material(row, fields) != expected:
                raise CanonicalizationConflict(conflict_message)
            return False
        connection.execute(sql, parameters)
        return True

    @staticmethod
    def _create_or_reuse_paper(
        connection: sqlite3.Connection,
        *,
        scheme: str,
        normalized: str,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        paper_id, should_create = ReviewedEvidenceCanonicalizationService._paper_id_for_identifier(
            connection, scheme, normalized
        )
        if not should_create:
            return paper_id, False
        identity_key = f"{scheme}:{normalized}"
        canonical_urn = f"qrh:evidence:paper:{paper_id}"
        event_id = stable_evidence_id("idevt", "paper-created/v1", paper_id)
        now = utc_now()
        connection.execute(
            """
            INSERT INTO paper_identity_event(
                identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
                normalized_value,provenance_urn,payload_json,occurred_at
            ) VALUES(?,'paper_created',NULL,?,NULL,NULL,?,?,?)
            """,
            (
                event_id,
                paper_id,
                provenance_urn,
                canonical_json({"identity_key": identity_key, "paper_urn": canonical_urn}),
                now,
            ),
        )
        connection.execute(
            "INSERT INTO paper(paper_id,canonical_urn,creation_event_id,created_at) VALUES(?,?,?,?)",
            (paper_id, canonical_urn, event_id, now),
        )
        return paper_id, True

    @staticmethod
    def _assign_identifier(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        candidate_id: str,
        scheme: str,
        normalized: str,
        provenance_urn: str,
    ) -> str:
        assertion_id = stable_evidence_id(
            "iassert", paper_id, scheme, normalized, provenance_urn
        )
        now = utc_now()
        ReviewedEvidenceCanonicalizationService._insert_exact(
            connection,
            table="paper_identifier_assertion",
            key_name="identifier_assertion_id",
            key=assertion_id,
            fields=(
                "paper_id", "candidate_id", "scheme", "raw_value",
                "normalized_value", "assertion_status", "provenance_urn",
            ),
            expected=(
                paper_id, candidate_id, scheme, normalized, normalized, "verified", provenance_urn
            ),
            sql="""
                INSERT INTO paper_identifier_assertion(
                    identifier_assertion_id,paper_id,candidate_id,scheme,raw_value,
                    normalized_value,assertion_status,provenance_urn,asserted_at
                ) VALUES(?,?,?,?,?,?,'verified',?,?)
            """,
            parameters=(
                assertion_id, paper_id, candidate_id, scheme, normalized,
                normalized, provenance_urn, now,
            ),
            conflict_message="reviewed identifier assertion conflicts",
        )
        current = connection.execute(
            "SELECT paper_id FROM identifier_assignment_projection WHERE scheme=? AND normalized_value=?",
            (scheme, normalized),
        ).fetchone()
        if current is not None:
            if current["paper_id"] != paper_id:
                raise CanonicalizationConflict("strong identifier belongs to another canonical paper")
            return assertion_id
        event_id = stable_evidence_id(
            "idevt", "identifier-assigned/v1", scheme, normalized, paper_id, "1"
        )
        connection.execute(
            """
            INSERT INTO paper_identity_event(
                identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
                normalized_value,provenance_urn,payload_json,occurred_at
            ) VALUES(?,'identifier_assigned',NULL,?,?,?,?,?,?)
            """,
            (
                event_id, paper_id, scheme, normalized, provenance_urn,
                canonical_json({"identifier_assertion_id": assertion_id, "revision": 1}), now,
            ),
        )
        connection.execute(
            """
            INSERT INTO identifier_assignment_projection(
                scheme,normalized_value,paper_id,source_event_id,revision,updated_at
            ) VALUES(?,?,?,?,1,?)
            """,
            (scheme, normalized, paper_id, event_id, now),
        )
        return assertion_id

    @staticmethod
    def _select_metadata(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        candidate_id: str,
        field_name: str,
        value: object,
        source_kind: str,
        provenance_urn: str,
    ) -> str:
        value_json = canonical_json(value)
        assertion_id = stable_evidence_id(
            "massert", paper_id, candidate_id, field_name, value_json, provenance_urn
        )
        now = utc_now()
        ReviewedEvidenceCanonicalizationService._insert_exact(
            connection,
            table="metadata_assertion",
            key_name="assertion_id",
            key=assertion_id,
            fields=(
                "paper_id", "candidate_id", "field_name", "value_json",
                "assertion_status", "source_kind", "provenance_urn",
            ),
            expected=(
                paper_id, candidate_id, field_name, value_json,
                "verified", source_kind, provenance_urn,
            ),
            sql="""
                INSERT INTO metadata_assertion(
                    assertion_id,paper_id,candidate_id,field_name,value_json,
                    assertion_status,source_kind,provenance_urn,asserted_at
                ) VALUES(?,?,?,?,?,'verified',?,?,?)
            """,
            parameters=(
                assertion_id, paper_id, candidate_id, field_name, value_json,
                source_kind, provenance_urn, now,
            ),
            conflict_message=f"verified {field_name} assertion conflicts",
        )
        current = connection.execute(
            """
            SELECT selection.selection_id,assertion.value_json
            FROM canonical_metadata_selection AS selection
            JOIN metadata_assertion AS assertion USING(assertion_id)
            WHERE selection.paper_id=? AND selection.field_name=?
            ORDER BY selection.selected_at DESC,selection.selection_id DESC LIMIT 1
            """,
            (paper_id, field_name),
        ).fetchone()
        if current is not None and current["value_json"] == value_json:
            return str(current["selection_id"])
        selection_id = stable_evidence_id(
            "msel", paper_id, field_name, assertion_id, provenance_urn
        )
        connection.execute(
            """
            INSERT INTO canonical_metadata_selection(
                selection_id,paper_id,field_name,assertion_id,
                supersedes_selection_id,provenance_urn,selected_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                selection_id, paper_id, field_name, assertion_id,
                str(current["selection_id"]) if current else None,
                provenance_urn, now,
            ),
        )
        return selection_id

    @staticmethod
    def _persist_people_categories_links(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        metadata: ReviewedMetadata,
    ) -> None:
        now = utc_now()
        existing_authors = connection.execute(
            """
            SELECT authorship.author_order,person.display_name
            FROM paper_authorship AS authorship JOIN person USING(person_id)
            WHERE authorship.paper_id=? ORDER BY authorship.author_order
            """,
            (paper_id,),
        ).fetchall()
        expected_names = [author.name for author in metadata.authors]
        if existing_authors:
            if [row["display_name"] for row in existing_authors] != expected_names:
                raise CanonicalizationConflict("reviewed authors conflict with canonical authorship")
        else:
            for order, author in enumerate(metadata.authors, start=1):
                person_id = stable_evidence_id(
                    "person", paper_id, str(order), author.name.casefold()
                )
                connection.execute(
                    "INSERT INTO person(person_id,display_name,orcid,provenance_urn) VALUES(?,?,NULL,?)",
                    (person_id, author.name, metadata.provenance_urn),
                )
                connection.execute(
                    """
                    INSERT INTO paper_authorship(
                        paper_id,person_id,author_order,role,provenance_urn
                    ) VALUES(?,?,?,'author',?)
                    """,
                    (paper_id, person_id, order, metadata.provenance_urn),
                )
                for organization_name in author.affiliations:
                    organization_id = stable_evidence_id(
                        "org", organization_name.casefold(), metadata.provenance_urn
                    )
                    connection.execute(
                        """
                        INSERT INTO organization(
                            organization_id,display_name,ror_id,provenance_urn
                        ) VALUES(?,?,NULL,?) ON CONFLICT(organization_id) DO NOTHING
                        """,
                        (organization_id, organization_name, metadata.provenance_urn),
                    )
                    affiliation_id = stable_evidence_id(
                        "aff", paper_id, person_id, organization_id, metadata.provenance_urn
                    )
                    connection.execute(
                        """
                        INSERT INTO person_affiliation_assertion(
                            affiliation_id,paper_id,person_id,organization_id,
                            provenance_urn,assertion_status,asserted_at
                        ) VALUES(?,?,?,?,?,'verified',?)
                        ON CONFLICT(affiliation_id) DO NOTHING
                        """,
                        (
                            affiliation_id, paper_id, person_id, organization_id,
                            metadata.provenance_urn, now,
                        ),
                    )
        category_assertion = metadata.category_assertion
        source_categories = [
            {
                **item.model_dump(mode="json"),
                "mapping": {
                    "fact_origin": metadata.category_fact_origin,
                    "mapped_categories": list(metadata.categories),
                    "primary_mapped_category": category_assertion.primary_mapped_category,
                },
            }
            for item in category_assertion.source_categories
        ]
        category_assertion_id = stable_evidence_id(
            "catassert",
            paper_id,
            category_assertion.source_system,
            category_assertion.mapping_policy_version,
            category_assertion.provenance_urn,
        )
        expected_category_assertion = (
            paper_id,
            category_assertion.source_system,
            canonical_json(source_categories),
            category_assertion.primary_source_category,
            category_assertion.mapping_policy_version,
            category_assertion.assertion_status,
            category_assertion.provenance_urn,
        )
        category_assertion_fields = (
            "paper_id", "source_system", "source_categories_json",
            "primary_source_category", "mapping_policy_version",
            "assertion_status", "provenance_urn",
        )
        existing_category_assertion = connection.execute(
            "SELECT * FROM paper_category_assertion WHERE paper_id=?", (paper_id,)
        ).fetchone()
        if existing_category_assertion is None:
            connection.execute(
                """
                INSERT INTO paper_category_assertion(
                    category_assertion_id,paper_id,source_system,
                    source_categories_json,primary_source_category,
                    mapping_policy_version,assertion_status,provenance_urn,asserted_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (category_assertion_id, *expected_category_assertion, now),
            )
            category_assignment_provenance = category_assertion.provenance_urn
        else:
            if _row_material(
                existing_category_assertion, category_assertion_fields
            ) != expected_category_assertion:
                raise CanonicalizationConflict(
                    "reviewed category source/mapping assertion conflicts"
                )
            category_assertion_id = str(
                existing_category_assertion["category_assertion_id"]
            )
            category_assignment_provenance = str(
                existing_category_assertion["provenance_urn"]
            )

        for category in metadata.categories:
            category_key = category.strip().casefold()
            category_id = stable_evidence_id("cat", category_key)
            connection.execute(
                """
                INSERT INTO paper_category(category_id,category_key,display_name)
                VALUES(?,?,?) ON CONFLICT(category_id) DO NOTHING
                """,
                (category_id, category_key, category),
            )
            row = connection.execute(
                "SELECT category_key,display_name FROM paper_category WHERE category_id=?",
                (category_id,),
            ).fetchone()
            if row is None or tuple(row) != (category_key, category):
                raise CanonicalizationConflict("reviewed category identity conflicts")
            connection.execute(
                """
                INSERT INTO paper_category_assignment(
                    paper_id,category_id,provenance_urn,assigned_at
                ) VALUES(?,?,?,?) ON CONFLICT DO NOTHING
                """,
                (paper_id, category_id, category_assignment_provenance, now),
            )
            is_primary = int(category == category_assertion.primary_mapped_category)
            detail_expected = (
                paper_id,
                category_id,
                category_assignment_provenance,
                is_primary,
                category_assertion_id,
            )
            detail = connection.execute(
                """
                SELECT paper_id,category_id,provenance_urn,is_primary,
                       category_assertion_id
                FROM paper_category_assignment_detail
                WHERE paper_id=? AND category_id=? AND provenance_urn=?
                """,
                (paper_id, category_id, category_assignment_provenance),
            ).fetchone()
            if detail is None:
                connection.execute(
                    """
                    INSERT INTO paper_category_assignment_detail(
                        paper_id,category_id,provenance_urn,is_primary,
                        category_assertion_id
                    ) VALUES(?,?,?,?,?)
                    """,
                    detail_expected,
                )
            elif tuple(detail) != detail_expected:
                raise CanonicalizationConflict(
                    "reviewed category assignment detail conflicts"
                )
        for link in metadata.external_links:
            link_id = stable_evidence_id(
                "link", paper_id, link.kind, link.url, metadata.provenance_urn
            )
            connection.execute(
                """
                INSERT INTO paper_external_link(
                    external_link_id,paper_id,candidate_id,link_kind,url,
                    verification_status,provenance_urn,asserted_at
                ) VALUES(?,?,NULL,?,?,?,?,?) ON CONFLICT(external_link_id) DO NOTHING
                """,
                (
                    link_id, paper_id, link.kind, link.url,
                    link.verification_status, metadata.provenance_urn, now,
                ),
            )

    @staticmethod
    def _persist_metadata_review(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        metadata: ReviewedMetadata,
    ) -> str | None:
        if not metadata.assertion_boundaries:
            return None
        analysis_text = canonical_json(metadata.assertion_boundaries)
        analysis_id = stable_evidence_id(
            "analysis",
            paper_id,
            "metadata_review",
            metadata.provenance_urn,
            analysis_text,
        )
        now = utc_now()
        ReviewedEvidenceCanonicalizationService._insert_exact(
            connection,
            table="paper_analysis",
            key_name="analysis_id",
            key=analysis_id,
            fields=(
                "paper_id",
                "analysis_kind",
                "analysis_text",
                "fact_status",
                "provenance_urn",
            ),
            expected=(
                paper_id,
                "metadata_review",
                analysis_text,
                "human_reviewed",
                metadata.provenance_urn,
            ),
            sql="""
                INSERT INTO paper_analysis(
                    analysis_id,paper_id,analysis_kind,analysis_text,
                    fact_status,provenance_urn,created_at
                ) VALUES(?,?,'metadata_review',?,'human_reviewed',?,?)
            """,
            parameters=(
                analysis_id,
                paper_id,
                analysis_text,
                metadata.provenance_urn,
                now,
            ),
            conflict_message="reviewed metadata boundary analysis conflicts",
        )
        return analysis_id

    @staticmethod
    def _persist_institution_resolution(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        resolution: ReviewedInstitutionResolution,
        provenance_urn: str,
    ) -> str:
        resolution_id = stable_evidence_id("instres", paper_id)
        expected = (
            paper_id,
            resolution.status,
            canonical_json(list(resolution.institutions)),
            resolution.reason_code,
            resolution.reason_text,
            canonical_json(list(resolution.checked_source_fields)),
            provenance_urn,
        )
        existing = connection.execute(
            "SELECT * FROM paper_institution_resolution WHERE paper_id=?", (paper_id,)
        ).fetchone()
        semantic_fields = (
            "paper_id", "resolution_status", "institutions_json", "reason_code",
            "reason_text", "checked_source_fields_json", "provenance_urn",
        )
        if existing is not None:
            if _row_material(existing, semantic_fields) != expected:
                raise CanonicalizationConflict("institution resolution conflicts")
            return str(existing["institution_resolution_id"])
        connection.execute(
            """
            INSERT INTO paper_institution_resolution(
                institution_resolution_id,paper_id,resolution_status,
                institutions_json,reason_code,reason_text,
                checked_source_fields_json,provenance_urn,resolved_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (resolution_id, *expected, utc_now()),
        )
        return resolution_id

    def _validate_resource(
        self,
        connection: sqlite3.Connection,
        *,
        item: ReviewedCanonicalizationItem,
        candidate_id: str,
    ) -> sqlite3.Row | None:
        if item.resource is None:
            return None
        # ``apply`` verified the content-addressed file before acquiring this write
        # transaction; do not open a second migrator connection under the write lock.
        row = connection.execute(
            """
            SELECT resource.*,fetch.requested_url,fetch.final_url,fetch.http_status,
                   fetch.legal_basis
            FROM paper_resource AS resource
            JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
            WHERE resource.resource_id=?
            """,
            (item.resource.resource_id,),
        ).fetchone()
        if row is None or row["verification_status"] != "verified" or row["media_type"] != "application/pdf":
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: resource is not a verified PDF"
            )
        if row["candidate_id"] != candidate_id and row["paper_id"] is None:
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: resource belongs to another resolution candidate"
            )
        acquired = connection.execute(
            """
            SELECT state.state
            FROM evidence_acquisition_case AS acquisition
            JOIN evidence_acquisition_state AS state USING(acquisition_case_id)
            JOIN evidence_acquisition_event AS event
              ON event.acquisition_case_id=acquisition.acquisition_case_id
             AND event.event_kind='fetch_succeeded'
             AND event.resource_id=?
            JOIN evidence_resource_offer AS offer USING(resource_offer_id)
            JOIN evidence_provider_observation AS observation USING(provider_observation_id)
            JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
            JOIN evidence_provider_request AS request USING(provider_request_id)
            WHERE acquisition.acquisition_case_id=?
              AND request.resolution_case_id=?
            """,
            (
                item.resource.resource_id,
                item.resource.acquisition_case_id,
                item.resolution_case_id,
            ),
        ).fetchone()
        if acquired is None or acquired["state"] != "acquired":
            raise CanonicalizationEligibilityError(
                f"{item.item_key}: resource lacks a completed rights-reviewed acquisition"
            )
        return row

    @staticmethod
    def _official_abstract_material(
        paper_id: str,
        excerpt: ReviewedExcerpt,
    ) -> tuple[str, str, tuple[object, ...]]:
        excerpt_hash = hashlib.sha256(excerpt.text.encode("utf-8")).hexdigest()
        source_kind = str(
            excerpt.locator.get("source_kind") or "official_source_abstract"
        )
        identity_kind = (
            "official-arxiv-atom-summary"
            if source_kind == "official_arxiv_atom_summary"
            else f"official-source-abstract:{source_kind}"
        )
        excerpt_id = stable_evidence_id(
            "excerpt",
            paper_id,
            identity_kind,
            excerpt_hash,
            excerpt.provenance_urn,
        )
        locator_json = canonical_json(
            {"page_sha256": excerpt.page_sha256, **excerpt.locator}
        )
        return (
            excerpt_id,
            excerpt_hash,
            (
                paper_id,
                None,
                excerpt.text,
                locator_json,
                excerpt_hash,
                excerpt.provenance_urn,
            ),
        )

    @staticmethod
    def _persist_official_abstract_excerpt(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        excerpt: ReviewedExcerpt | None,
    ) -> tuple[str | None, str | None]:
        if excerpt is None:
            return None, None
        excerpt_id, excerpt_hash, expected = (
            ReviewedEvidenceCanonicalizationService._official_abstract_material(
                paper_id, excerpt
            )
        )
        ReviewedEvidenceCanonicalizationService._insert_exact(
            connection,
            table="evidence_excerpt",
            key_name="excerpt_id",
            key=excerpt_id,
            fields=(
                "paper_id", "resource_id", "excerpt_text", "locator_json",
                "excerpt_sha256", "provenance_urn",
            ),
            expected=expected,
            sql="""
                INSERT INTO evidence_excerpt(
                    excerpt_id,paper_id,resource_id,excerpt_text,locator_json,
                    excerpt_sha256,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
            """,
            parameters=(excerpt_id, *expected, utc_now()),
            conflict_message="reviewed official abstract excerpt conflicts",
        )
        return excerpt_id, excerpt_hash

    @staticmethod
    def _persist_resource_and_reading(
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        item: ReviewedCanonicalizationItem,
        paper_id: str,
        resource: sqlite3.Row,
        official_abstract_excerpt_id: str,
        provenance_urn: str,
    ) -> tuple[str, str, str | None, dict[str, object]]:
        assert item.resource is not None
        assert item.official_abstract_excerpt is not None
        now = utc_now()
        attachment_id = stable_evidence_id(
            "resattach", paper_id, item.resource.resource_id
        )
        existing_attachment = connection.execute(
            "SELECT * FROM evidence_canonical_resource_attachment WHERE paper_id=? AND resource_id=?",
            (paper_id, item.resource.resource_id),
        ).fetchone()
        if existing_attachment is None:
            connection.execute(
                """
                INSERT INTO evidence_canonical_resource_attachment(
                    resource_attachment_id,canonicalization_receipt_id,resolution_case_id,
                    paper_id,resource_id,provenance_urn,attached_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    attachment_id, receipt_id, item.resolution_case_id, paper_id,
                    item.resource.resource_id, provenance_urn, now,
                ),
            )
        else:
            attachment_id = str(existing_attachment["resource_attachment_id"])
        excerpt = item.official_abstract_excerpt
        excerpt_hash = hashlib.sha256(excerpt.text.encode("utf-8")).hexdigest()
        input_hash = _sha256_json(
            {
                "abstract_page_sha256": excerpt.page_sha256,
                "abstract_sha256": excerpt_hash,
                "pdf_bytes": int(resource["bytes"]),
                "pdf_sha256": str(resource["content_sha256"]),
            }
        )
        task_id = stable_evidence_id("readtask", paper_id, input_hash)
        objective = (
            "基于已复核 PDF 与来源摘要完成独立全文精读；区分来源事实、模型推断和人工审核结论，"
            "并为核心结论保留可回指的证据边界。"
        )
        required_outputs = canonical_json(
            {
                "analysis": "required",
                "core_conclusions": "required_with_source_locators",
                "fact_boundary": "required",
            }
        )
        existing_task = connection.execute(
            "SELECT * FROM paper_reading_task WHERE paper_id=?", (paper_id,)
        ).fetchone()
        task_expected = (
            paper_id, item.resource.resource_id, official_abstract_excerpt_id, input_hash,
            objective, required_outputs, provenance_urn,
        )
        if existing_task is None:
            connection.execute(
                """
                INSERT INTO paper_reading_task(
                    reading_task_id,paper_id,resource_id,abstract_excerpt_id,
                    input_snapshot_hash,objective_text,required_outputs_json,
                    provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (task_id, *task_expected, now),
            )
        elif _row_material(
            existing_task,
            (
                "paper_id", "resource_id", "abstract_excerpt_id", "input_snapshot_hash",
                "objective_text", "required_outputs_json", "provenance_urn",
            ),
        ) != task_expected:
            raise CanonicalizationConflict("canonical paper already has a different reading task")
        else:
            task_id = str(existing_task["reading_task_id"])

        run_id: str | None = None
        reading_payload: dict[str, object] = {}
        if item.resource.reading_result is not None:
            reviewed = item.resource.reading_result
            reading_payload = {
                "analysis": reviewed.analysis,
                "core_conclusions": [
                    value.model_dump(mode="json") for value in reviewed.core_conclusions
                ],
                "fact_boundary": reviewed.fact_boundary,
            }
            run_key = f"canonicalization:{receipt_id}:reading"
            run_id = stable_evidence_id(
                "readrun", task_id, run_key, reviewed.provenance_urn
            )
            existing_run = connection.execute(
                "SELECT * FROM paper_reading_run WHERE reading_run_id=?", (run_id,)
            ).fetchone()
            analysis_json = canonical_json(reading_payload)
            if existing_run is None:
                prior_success = connection.execute(
                    "SELECT * FROM paper_reading_run WHERE reading_task_id=? AND result_status='succeeded'",
                    (task_id,),
                ).fetchone()
                if prior_success is not None:
                    if prior_success["analysis_payload_json"] != analysis_json:
                        raise CanonicalizationConflict(
                            "canonical reading task already has a different successful result"
                        )
                    run_id = str(prior_success["reading_run_id"])
                else:
                    attempt = int(
                        connection.execute(
                            "SELECT COALESCE(max(attempt_number),0)+1 FROM paper_reading_run WHERE reading_task_id=?",
                            (task_id,),
                        ).fetchone()[0]
                    )
                    connection.execute(
                        """
                        INSERT INTO paper_reading_run(
                            reading_run_id,reading_task_id,attempt_number,idempotency_key,
                            worker_kind,input_snapshot_hash,result_status,
                            analysis_payload_json,failure_json,provenance_urn,completed_at
                        ) VALUES(?,?,?,?,?,?,'succeeded',?,NULL,?,?)
                        """,
                        (
                            run_id, task_id, attempt, run_key, reviewed.worker_kind,
                            input_hash, analysis_json, reviewed.provenance_urn, now,
                        ),
                    )
            elif (
                existing_run["reading_task_id"] != task_id
                or existing_run["result_status"] != "succeeded"
                or existing_run["analysis_payload_json"] != analysis_json
            ):
                raise CanonicalizationConflict("reviewed reading result conflicts")
        return attachment_id, task_id, run_id, reading_payload

    @staticmethod
    def _persist_conclusions(
        connection: sqlite3.Connection,
        *,
        item: ReviewedCanonicalizationItem,
        paper_id: str,
        excerpt_id: str | None,
        reading_run_id: str | None,
        resource_id: str | None,
    ) -> list[dict[str, str]]:
        output: list[dict[str, str]] = []
        for conclusion in item.core_conclusions:
            conclusion_id = stable_evidence_id(
                "conclusion", paper_id, conclusion.text, conclusion.provenance_urn
            )
            fact_status = (
                "source_claim"
                if conclusion.evidence_scope == "official_abstract"
                else "human_reviewed"
            )
            connection.execute(
                """
                INSERT INTO paper_core_conclusion(
                    conclusion_id,paper_id,conclusion_text,fact_status,
                    provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?) ON CONFLICT(conclusion_id) DO NOTHING
                """,
                (
                    conclusion_id, paper_id, conclusion.text, fact_status,
                    conclusion.provenance_urn, utc_now(),
                ),
            )
            if conclusion.evidence_scope == "official_abstract":
                if excerpt_id is None:
                    raise CanonicalizationEligibilityError(
                        "abstract conclusion requires its reviewed excerpt"
                    )
                connection.execute(
                    """
                    INSERT INTO paper_core_conclusion_evidence(
                        conclusion_id,excerpt_id,claim_scope,verification_status,
                        provenance_urn,linked_at
                    ) VALUES(?,?,'official_abstract_verbatim',
                             'source_verified_not_fulltext_reviewed',?,?)
                    ON CONFLICT(conclusion_id) DO NOTHING
                    """,
                    (
                        conclusion_id, excerpt_id,
                        conclusion.provenance_urn, utc_now(),
                    ),
                )
            else:
                if reading_run_id is None:
                    raise CanonicalizationEligibilityError(
                        "full-text conclusion requires a successful reviewed reading run"
                    )
                connection.execute(
                    """
                    INSERT INTO paper_reading_conclusion_binding(
                        reading_run_id,conclusion_id,provenance_urn,linked_at
                    ) VALUES(?,?,?,?) ON CONFLICT DO NOTHING
                    """,
                    (
                        reading_run_id, conclusion_id,
                        conclusion.provenance_urn, utc_now(),
                    ),
                )
                if resource_id is None or conclusion.source_locator is None:
                    raise CanonicalizationEligibilityError(
                        "full-text conclusion requires its verified resource locator"
                    )
                locator = conclusion.source_locator
                connection.execute(
                    """
                    INSERT INTO evidence_fulltext_conclusion_support(
                        conclusion_id,resource_id,page_number,page_text_sha256,
                        support_text_sha256,locator_json,verification_status,
                        provenance_urn,linked_at
                    ) VALUES(?,?,?,?,?,?,'reviewed_fulltext_locator',?,?)
                    ON CONFLICT(conclusion_id) DO NOTHING
                    """,
                    (
                        conclusion_id, resource_id, locator.page_number,
                        locator.page_text_sha256, locator.support_text_sha256,
                        canonical_json(locator.locator), conclusion.provenance_urn,
                        utc_now(),
                    ),
                )
            output.append(
                {
                    "text": conclusion.text,
                    "fact_status": fact_status,
                    "provenance_urn": conclusion.provenance_urn,
                    "evidence_scope": conclusion.evidence_scope,
                    "source_locator": (
                        conclusion.source_locator.model_dump(mode="json")
                        if conclusion.source_locator is not None
                        else None
                    ),
                }
            )
        return output

    @staticmethod
    def _bind_formal_citations(
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        rows: list[sqlite3.Row],
        paper_id: str,
        provenance_urn: str,
    ) -> tuple[list[str], list[str]]:
        bindings: list[str] = []
        relations: list[str] = []
        for row in rows:
            ledger_id = str(row["ledger_entry_id"])
            binding_id = stable_evidence_id(
                "bind", ledger_id, paper_id, "resolved", provenance_urn
            )
            rationale = (
                "由已审核 strong-identifier identity decision 解析并规范绑定；"
                f"canonicalization receipt={receipt_id}。"
            )
            existing_binding = connection.execute(
                "SELECT * FROM citation_binding WHERE binding_id=?", (binding_id,)
            ).fetchone()
            expected = (ledger_id, paper_id, "resolved", rationale, provenance_urn)
            if existing_binding is None:
                connection.execute(
                    """
                    INSERT INTO citation_binding(
                        binding_id,ledger_entry_id,paper_id,binding_status,rationale,
                        provenance_urn,created_at
                    ) VALUES(?,?,?,'resolved',?,?,?)
                    """,
                    (binding_id, ledger_id, paper_id, rationale, provenance_urn, utc_now()),
                )
            elif _row_material(
                existing_binding,
                ("ledger_entry_id", "paper_id", "binding_status", "rationale", "provenance_urn"),
            ) != expected:
                raise CanonicalizationConflict("resolved citation binding conflicts")
            current = connection.execute(
                "SELECT * FROM citation_binding_projection WHERE ledger_entry_id=?",
                (ledger_id,),
            ).fetchone()
            if current is None or current["binding_id"] != binding_id:
                revision = 1 if current is None else int(current["revision"]) + 1
                event_kind = "binding_created" if current is None else "binding_revised"
                supersedes = None if current is None else str(current["source_event_id"])
                event_id = stable_evidence_id(
                    "bevt", ledger_id, binding_id, str(revision)
                )
                connection.execute(
                    """
                    INSERT INTO citation_binding_event(
                        binding_event_id,ledger_entry_id,binding_id,event_kind,
                        supersedes_event_id,provenance_urn,occurred_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        event_id, ledger_id, binding_id, event_kind,
                        supersedes, provenance_urn, utc_now(),
                    ),
                )
                if current is None:
                    connection.execute(
                        """
                        INSERT INTO citation_binding_projection(
                            ledger_entry_id,binding_id,source_event_id,revision,updated_at
                        ) VALUES(?,?,?,?,?)
                        """,
                        (ledger_id, binding_id, event_id, revision, utc_now()),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE citation_binding_projection
                        SET binding_id=?,source_event_id=?,revision=?,updated_at=?
                        WHERE ledger_entry_id=?
                        """,
                        (binding_id, event_id, revision, utc_now(), ledger_id),
                    )
            bindings.append(binding_id)
            occurrence_kind = str(row["occurrence_kind"])
            relation_kind = (
                "formal_reference"
                if occurrence_kind in {"strong_identifier", "formal_reference"}
                else "mentions"
                if occurrence_kind == "textual_mention"
                else "method_uses"
            )
            relation_id = stable_evidence_id(
                "relation", ledger_id, paper_id, relation_kind
            )
            existing_relation = connection.execute(
                "SELECT * FROM research_paper_relation WHERE relation_id=?", (relation_id,)
            ).fetchone()
            relation_expected = (
                str(row["research_urn"]), str(row["document_version_urn"]),
                ledger_id, str(row["citation_id"]), paper_id,
                relation_kind, provenance_urn,
            )
            if existing_relation is None:
                connection.execute(
                    """
                    INSERT INTO research_paper_relation(
                        relation_id,research_urn,document_version_urn,ledger_entry_id,
                        citation_id,paper_id,relation_kind,provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (relation_id, *relation_expected, utc_now()),
                )
            elif _row_material(
                existing_relation,
                (
                    "research_urn", "document_version_urn", "ledger_entry_id",
                    "citation_id", "paper_id", "relation_kind", "provenance_urn",
                ),
            ) != relation_expected:
                raise CanonicalizationConflict("research-paper relation conflicts")
            relations.append(relation_id)
        return bindings, relations

    @staticmethod
    def _associate_method_origins(
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        item: ReviewedCanonicalizationItem,
        rows: list[sqlite3.Row],
        paper_id: str,
        provenance_urn: str,
    ) -> list[str]:
        assert item.association_rationale is not None
        output: list[str] = []
        for row in rows:
            association_id = stable_evidence_id(
                "assoc", str(row["ledger_entry_id"]), paper_id, "associated_method_origin"
            )
            existing = connection.execute(
                "SELECT * FROM evidence_associated_method_relation WHERE associated_relation_id=?",
                (association_id,),
            ).fetchone()
            expected = (
                receipt_id, item.source_candidate_id, str(row["ledger_entry_id"]),
                str(row["citation_id"]), paper_id, "associated_method_origin",
                item.association_rationale, provenance_urn,
            )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO evidence_associated_method_relation(
                        associated_relation_id,canonicalization_receipt_id,
                        source_candidate_id,ledger_entry_id,citation_id,paper_id,
                        association_kind,rationale,provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,?,'associated_method_origin',?,?,?)
                    """,
                    (
                        association_id, receipt_id, item.source_candidate_id,
                        row["ledger_entry_id"], row["citation_id"], paper_id,
                        item.association_rationale, provenance_urn, utc_now(),
                    ),
                )
            elif _row_material(
                existing,
                (
                    "canonicalization_receipt_id", "source_candidate_id",
                    "ledger_entry_id", "citation_id", "paper_id",
                    "association_kind", "rationale", "provenance_urn",
                ),
            ) != expected:
                raise CanonicalizationConflict("associated method-origin relation conflicts")
            output.append(association_id)
        return output

    @staticmethod
    def _project_catalog(
        connection: sqlite3.Connection,
        *,
        paper_id: str,
        item: ReviewedCanonicalizationItem,
        conclusions: list[dict[str, str]],
        resource: sqlite3.Row | None,
    ) -> None:
        authors = [author.model_dump(mode="json") for author in item.metadata.authors]
        resources = (
            [
                {
                    "resource_id": str(resource["resource_id"]),
                    "url": f"/api/v1/evidence/resources/{resource['resource_id']}",
                    "sha256": str(resource["content_sha256"]),
                    "bytes": int(resource["bytes"]),
                }
            ]
            if resource is not None
            else []
        )
        existing = connection.execute(
            "SELECT * FROM paper_catalog_projection WHERE paper_id=?", (paper_id,)
        ).fetchone()
        retained_conclusions = conclusions
        retained_resources = resources
        if existing is not None:
            # A method-origin association or a metadata-only citation is evidence about
            # the relationship, not authority to erase previously reviewed paper bytes
            # or conclusions.  New non-empty reviewed material must still match/update.
            if not conclusions:
                retained_conclusions = json.loads(str(existing["core_conclusions_json"]))
            if resource is None:
                retained_resources = json.loads(str(existing["local_resources_json"]))
        projected = (
            item.metadata.title,
            item.metadata.publication_date,
            canonical_json(authors),
            canonical_json(list(item.metadata.institutions.institutions)),
            canonical_json(list(item.metadata.categories)),
            canonical_json(retained_conclusions),
            canonical_json(
                [link.model_dump(mode="json") for link in item.metadata.external_links]
            ),
            canonical_json(retained_resources),
            "partial",
        )
        fields = (
            "title", "publication_date", "authors_json", "institutions_json",
            "categories_json", "core_conclusions_json", "external_links_json",
            "local_resources_json", "verification_status",
        )
        if existing is None:
            connection.execute(
                """
                INSERT INTO paper_catalog_projection(
                    paper_id,title,publication_date,authors_json,institutions_json,
                    categories_json,core_conclusions_json,external_links_json,
                    local_resources_json,verification_status,projection_revision,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,1,?)
                """,
                (paper_id, *projected, utc_now()),
            )
        elif _row_material(existing, fields) != projected:
            connection.execute(
                """
                UPDATE paper_catalog_projection
                SET title=?,publication_date=?,authors_json=?,institutions_json=?,
                    categories_json=?,core_conclusions_json=?,external_links_json=?,
                    local_resources_json=?,verification_status=?,
                    projection_revision=projection_revision+1,updated_at=?
                WHERE paper_id=?
                """,
                (*projected, utc_now(), paper_id),
            )

    @staticmethod
    def _record_event(
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        sequence: int,
        kind: str,
        entity_urn: str,
        payload: dict[str, object],
    ) -> str:
        event_id = stable_evidence_id(
            "canonevt", receipt_id, str(sequence), kind, entity_urn
        )
        payload_json = canonical_json(payload)
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO evidence_canonicalization_event(
                canonicalization_event_id,canonicalization_receipt_id,event_sequence,
                event_kind,entity_urn,payload_json,payload_sha256,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                event_id, receipt_id, sequence, kind, entity_urn,
                payload_json, payload_hash, utc_now(),
            ),
        )
        return event_id

    @staticmethod
    def _verify_replay(
        connection: sqlite3.Connection,
        *,
        receipt: sqlite3.Row,
        manifest_hash: str,
        item_hash: str,
        item: ReviewedCanonicalizationItem,
    ) -> CanonicalizationItemResult:
        expected = (
            SCHEMA_VERSION,
            manifest_hash,
            item.item_key,
            item_hash,
            item.treatment,
            item.source_candidate_id,
            item.paper_source_candidate_id,
            item.resolution_case_id,
            item.identity_decision_id,
        )
        actual = _row_material(
            receipt,
            (
                "manifest_schema_version", "manifest_sha256", "item_key",
                "item_material_sha256", "treatment", "source_candidate_id",
                "paper_source_candidate_id", "resolution_case_id", "identity_decision_id",
            ),
        )
        if actual != expected:
            raise CanonicalizationConflict(
                f"{item.item_key}: idempotency key is bound to different material"
            )
        paper_id = str(receipt["paper_id"])
        decision = ReviewedEvidenceCanonicalizationService._decision_material(
            connection, item
        )
        rows = ReviewedEvidenceCanonicalizationService._ledger_rows(
            connection, item.source_candidate_id
        )
        official_abstract_excerpt_id: str | None = None
        official_abstract_sha256: str | None = None
        if item.official_abstract_excerpt is not None:
            (
                official_abstract_excerpt_id,
                official_abstract_sha256,
                excerpt_expected,
            ) = ReviewedEvidenceCanonicalizationService._official_abstract_material(
                paper_id, item.official_abstract_excerpt
            )
            excerpt_row = connection.execute(
                "SELECT * FROM evidence_excerpt WHERE excerpt_id=?",
                (official_abstract_excerpt_id,),
            ).fetchone()
            if excerpt_row is None or _row_material(
                excerpt_row,
                (
                    "paper_id", "resource_id", "excerpt_text", "locator_json",
                    "excerpt_sha256", "provenance_urn",
                ),
            ) != excerpt_expected:
                raise CanonicalizationConflict(
                    "canonicalization receipt lost its official abstract evidence"
                )
        resource_id = item.resource.resource_id if item.resource is not None else None
        expected_resource_mode = (
            "verified_local_resource" if resource_id is not None else "metadata_only"
        )
        expected_result_hash = (
            ReviewedEvidenceCanonicalizationService._result_material_sha256(
                item_material_sha256=item_hash,
                paper_id=paper_id,
                identifier_scheme=str(decision["identifier_scheme"]),
                normalized_identifier=str(decision["normalized_identifier"]),
                ledger_entry_ids=[str(row["ledger_entry_id"]) for row in rows],
                resource_id=resource_id,
                official_abstract_excerpt_id=official_abstract_excerpt_id,
                official_abstract_sha256=official_abstract_sha256,
            )
        )
        if (
            receipt["resource_mode"] != expected_resource_mode
            or receipt["result_material_sha256"] != expected_result_hash
        ):
            raise CanonicalizationConflict(
                "canonicalization receipt result material cannot be replayed"
            )
        events = connection.execute(
            """
            SELECT * FROM evidence_canonicalization_event
            WHERE canonicalization_receipt_id=? ORDER BY event_sequence
            """,
            (receipt["canonicalization_receipt_id"],),
        ).fetchall()
        if not events or events[-1]["event_kind"] != "application_committed":
            raise CanonicalizationConflict("canonicalization receipt lacks a commit event")
        for event in events:
            if hashlib.sha256(str(event["payload_json"]).encode("utf-8")).hexdigest() != event["payload_sha256"]:
                raise CanonicalizationConflict("canonicalization event payload hash changed")
        state = connection.execute(
            "SELECT state,revision,source_event_id FROM evidence_canonicalization_state WHERE canonicalization_receipt_id=?",
            (receipt["canonicalization_receipt_id"],),
        ).fetchone()
        if state is None or tuple(state) != (
            "applied", 1, str(events[-1]["canonicalization_event_id"])
        ):
            raise CanonicalizationConflict("canonicalization state cannot be replayed")
        committed = json.loads(str(events[-1]["payload_json"]))
        metadata_events = [
            event for event in events if event["event_kind"] == "metadata_selected"
        ]
        if len(metadata_events) != 1:
            raise CanonicalizationConflict(
                "canonicalization receipt lacks one metadata selection event"
            )
        metadata_payload = json.loads(str(metadata_events[0]["payload_json"]))
        expected_excerpt_binding = {
            "official_abstract_excerpt_id": official_abstract_excerpt_id,
            "official_abstract_sha256": official_abstract_sha256,
        }
        if item.official_abstract_excerpt is not None:
            if any(
                metadata_payload.get(key) != value
                or committed.get(key) != value
                for key, value in expected_excerpt_binding.items()
            ):
                raise CanonicalizationConflict(
                    "canonicalization events lost their official abstract binding"
                )
        if committed.get("result_material_sha256") != expected_result_hash:
            raise CanonicalizationConflict(
                "canonicalization commit event result hash changed"
            )
        return CanonicalizationItemResult(
            receipt_id=str(receipt["canonicalization_receipt_id"]),
            item_key=item.item_key,
            paper_id=paper_id,
            treatment=item.treatment,
            resource_mode=str(receipt["resource_mode"]),
            bound_citations=int(committed.get("bound_citations", 0)),
            associated_relations=int(committed.get("associated_relations", 0)),
            created=False,
        )

    def apply(
        self, manifest: ReviewedCanonicalizationManifest
    ) -> CanonicalizationApplyResult:
        self.repository.initialize()
        manifest_hash = _sha256_json(manifest.model_dump(mode="json"))
        # Verify bytes before taking the write lock; no filesystem write occurs here.
        for item in manifest.items:
            if item.resource is not None:
                self.resource_store.resource_response(item.resource.resource_id)
        results: list[CanonicalizationItemResult] = []
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            for item in manifest.items:
                item_hash = _sha256_json(item.model_dump(mode="json"))
                receipt_id = self._receipt_id(manifest, item.item_key)
                existing_receipt = connection.execute(
                    "SELECT * FROM evidence_canonicalization_receipt WHERE canonicalization_receipt_id=?",
                    (receipt_id,),
                ).fetchone()
                if existing_receipt is not None:
                    results.append(
                        self._verify_replay(
                            connection,
                            receipt=existing_receipt,
                            manifest_hash=manifest_hash,
                            item_hash=item_hash,
                            item=item,
                        )
                    )
                    continue
                decision = self._decision_material(connection, item)
                candidate_id = str(decision["candidate_id"])
                scheme = str(decision["identifier_scheme"])
                normalized = str(decision["normalized_identifier"])
                paper_id, paper_created = self._create_or_reuse_paper(
                    connection,
                    scheme=scheme,
                    normalized=normalized,
                    provenance_urn=manifest.provenance_urn,
                )
                identifier_assertion_id = self._assign_identifier(
                    connection,
                    paper_id=paper_id,
                    candidate_id=candidate_id,
                    scheme=scheme,
                    normalized=normalized,
                    provenance_urn=(
                        f"{manifest.provenance_urn}:identity-decision:"
                        f"{item.identity_decision_id}"
                    ),
                )
                resource_row = self._validate_resource(
                    connection, item=item, candidate_id=candidate_id
                )
                rows = self._ledger_rows(connection, item.source_candidate_id)
                if not rows:
                    raise CanonicalizationEligibilityError(
                        f"{item.item_key}: source candidate has no Archive citation ledger entries"
                    )
                resource_mode = (
                    "verified_local_resource" if resource_row is not None else "metadata_only"
                )
                official_abstract_excerpt_id: str | None = None
                official_abstract_sha256: str | None = None
                if item.official_abstract_excerpt is not None:
                    (
                        official_abstract_excerpt_id,
                        official_abstract_sha256,
                        _,
                    ) = self._official_abstract_material(
                        paper_id, item.official_abstract_excerpt
                    )
                result_hash = self._result_material_sha256(
                    item_material_sha256=item_hash,
                    paper_id=paper_id,
                    identifier_scheme=scheme,
                    normalized_identifier=normalized,
                    ledger_entry_ids=[str(row["ledger_entry_id"]) for row in rows],
                    resource_id=(
                        str(resource_row["resource_id"])
                        if resource_row is not None
                        else None
                    ),
                    official_abstract_excerpt_id=official_abstract_excerpt_id,
                    official_abstract_sha256=official_abstract_sha256,
                )
                connection.execute(
                    """
                    INSERT INTO evidence_canonicalization_receipt(
                        canonicalization_receipt_id,manifest_schema_version,
                        manifest_sha256,item_key,item_material_sha256,idempotency_key,
                        treatment,source_candidate_id,paper_source_candidate_id,
                        resolution_case_id,identity_decision_id,paper_id,resource_mode,
                        result_material_sha256,provenance_urn,applied_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        receipt_id, SCHEMA_VERSION, manifest_hash, item.item_key,
                        item_hash, manifest.idempotency_key, item.treatment,
                        item.source_candidate_id, item.paper_source_candidate_id,
                        item.resolution_case_id, item.identity_decision_id, paper_id,
                        resource_mode, result_hash, manifest.provenance_urn, utc_now(),
                    ),
                )
                sequence = 1
                self._record_event(
                    connection,
                    receipt_id=receipt_id,
                    sequence=sequence,
                    kind="paper_created" if paper_created else "paper_reused",
                    entity_urn=f"qrh:evidence:paper:{paper_id}",
                    payload={"paper_id": paper_id, "identity_key": f"{scheme}:{normalized}"},
                )
                sequence += 1
                self._record_event(
                    connection,
                    receipt_id=receipt_id,
                    sequence=sequence,
                    kind="identifier_assigned",
                    entity_urn=f"qrh:evidence:identifier:{scheme}:{normalized}",
                    payload={"identifier_assertion_id": identifier_assertion_id},
                )
                metadata = item.metadata
                selection_ids = [
                    self._select_metadata(
                        connection,
                        paper_id=paper_id,
                        candidate_id=candidate_id,
                        field_name="title",
                        value=metadata.title,
                        source_kind=metadata.source_kind,
                        provenance_urn=metadata.provenance_urn,
                    )
                ]
                if metadata.publication_date is not None:
                    selection_ids.append(
                        self._select_metadata(
                            connection,
                            paper_id=paper_id,
                            candidate_id=candidate_id,
                            field_name="publication_date",
                            value=metadata.publication_date,
                            source_kind=metadata.source_kind,
                            provenance_urn=metadata.provenance_urn,
                        )
                    )
                if metadata.authors:
                    selection_ids.append(
                        self._select_metadata(
                            connection,
                            paper_id=paper_id,
                            candidate_id=candidate_id,
                            field_name="author",
                            value=[author.model_dump(mode="json") for author in metadata.authors],
                            source_kind=metadata.source_kind,
                            provenance_urn=metadata.provenance_urn,
                        )
                    )
                if item.official_abstract_excerpt is not None:
                    selection_ids.append(
                        self._select_metadata(
                            connection,
                            paper_id=paper_id,
                            candidate_id=candidate_id,
                            field_name="abstract",
                            value=item.official_abstract_excerpt.text,
                            source_kind=metadata.source_kind,
                            provenance_urn=item.official_abstract_excerpt.provenance_urn,
                        )
                    )
                if metadata.venue is not None:
                    selection_ids.append(
                        self._select_metadata(
                            connection,
                            paper_id=paper_id,
                            candidate_id=candidate_id,
                            field_name="venue",
                            value=metadata.venue.model_dump(mode="json"),
                            source_kind=metadata.source_kind,
                            provenance_urn=metadata.venue.provenance_urn,
                        )
                    )
                self._persist_people_categories_links(
                    connection, paper_id=paper_id, metadata=metadata
                )
                metadata_review_id = self._persist_metadata_review(
                    connection, paper_id=paper_id, metadata=metadata
                )
                persisted_excerpt_id, persisted_excerpt_sha256 = (
                    self._persist_official_abstract_excerpt(
                        connection,
                        paper_id=paper_id,
                        excerpt=item.official_abstract_excerpt,
                    )
                )
                if (
                    persisted_excerpt_id != official_abstract_excerpt_id
                    or persisted_excerpt_sha256 != official_abstract_sha256
                ):
                    raise CanonicalizationConflict(
                        "official abstract persistence differs from receipt material"
                    )
                metadata_event_payload: dict[str, object] = {
                    "selection_ids": selection_ids,
                    "metadata_review_id": metadata_review_id,
                }
                if official_abstract_excerpt_id is not None:
                    metadata_event_payload.update(
                        {
                            "official_abstract_excerpt_id": official_abstract_excerpt_id,
                            "official_abstract_sha256": official_abstract_sha256,
                        }
                    )
                sequence += 1
                self._record_event(
                    connection,
                    receipt_id=receipt_id,
                    sequence=sequence,
                    kind="metadata_selected",
                    entity_urn=f"qrh:evidence:paper:{paper_id}:metadata",
                    payload=metadata_event_payload,
                )
                institution_id = self._persist_institution_resolution(
                    connection,
                    paper_id=paper_id,
                    resolution=metadata.institutions,
                    provenance_urn=metadata.provenance_urn,
                )
                sequence += 1
                self._record_event(
                    connection,
                    receipt_id=receipt_id,
                    sequence=sequence,
                    kind="institution_recorded",
                    entity_urn=f"qrh:evidence:institution-resolution:{institution_id}",
                    payload={"status": metadata.institutions.status},
                )
                reading_run_id: str | None = None
                if resource_row is not None:
                    if official_abstract_excerpt_id is None:
                        raise CanonicalizationEligibilityError(
                            "verified local resource lacks official abstract evidence"
                        )
                    attachment_id, task_id, reading_run_id, _ = self._persist_resource_and_reading(
                        connection,
                        receipt_id=receipt_id,
                        item=item,
                        paper_id=paper_id,
                        resource=resource_row,
                        official_abstract_excerpt_id=official_abstract_excerpt_id,
                        provenance_urn=manifest.provenance_urn,
                    )
                    assert item.resource is not None
                    sequence += 1
                    self._record_event(
                        connection,
                        receipt_id=receipt_id,
                        sequence=sequence,
                        kind="resource_attached",
                        entity_urn=f"qrh:evidence:resource:{resource_row['resource_id']}",
                        payload={
                            "resource_attachment_id": attachment_id,
                            "sha256": str(resource_row["content_sha256"]),
                            "bytes": int(resource_row["bytes"]),
                            "media_type": str(resource_row["media_type"]),
                            "rights_status": str(resource_row["rights_status"]),
                            "fetch_attempt_id": str(resource_row["fetch_attempt_id"]),
                        },
                    )
                    sequence += 1
                    self._record_event(
                        connection,
                        receipt_id=receipt_id,
                        sequence=sequence,
                        kind="reading_task_created",
                        entity_urn=f"qrh:evidence:reading-task:{task_id}",
                        payload={"reading_task_id": task_id, "input_resource_id": item.resource.resource_id},
                    )
                    if reading_run_id is not None:
                        sequence += 1
                        self._record_event(
                            connection,
                            receipt_id=receipt_id,
                            sequence=sequence,
                            kind="reading_result_recorded",
                            entity_urn=f"qrh:evidence:reading-run:{reading_run_id}",
                            payload={"reading_run_id": reading_run_id, "result_status": "succeeded"},
                        )
                conclusions = self._persist_conclusions(
                    connection,
                    item=item,
                    paper_id=paper_id,
                    excerpt_id=official_abstract_excerpt_id,
                    reading_run_id=reading_run_id,
                    resource_id=(
                        str(resource_row["resource_id"])
                        if resource_row is not None
                        else None
                    ),
                )
                bound_ids: list[str] = []
                relation_ids: list[str] = []
                association_ids: list[str] = []
                if item.treatment == "formal_citation":
                    bound_ids, relation_ids = self._bind_formal_citations(
                        connection,
                        receipt_id=receipt_id,
                        rows=rows,
                        paper_id=paper_id,
                        provenance_urn=manifest.provenance_urn,
                    )
                    for binding_id in bound_ids:
                        sequence += 1
                        self._record_event(
                            connection,
                            receipt_id=receipt_id,
                            sequence=sequence,
                            kind="citation_bound",
                            entity_urn=f"qrh:evidence:citation-binding:{binding_id}",
                            payload={"binding_id": binding_id, "paper_id": paper_id},
                        )
                    for relation_id in relation_ids:
                        sequence += 1
                        self._record_event(
                            connection,
                            receipt_id=receipt_id,
                            sequence=sequence,
                            kind="research_relation_added",
                            entity_urn=f"qrh:evidence:research-relation:{relation_id}",
                            payload={"relation_id": relation_id, "paper_id": paper_id},
                        )
                else:
                    association_ids = self._associate_method_origins(
                        connection,
                        receipt_id=receipt_id,
                        item=item,
                        rows=rows,
                        paper_id=paper_id,
                        provenance_urn=manifest.provenance_urn,
                    )
                    for association_id in association_ids:
                        sequence += 1
                        self._record_event(
                            connection,
                            receipt_id=receipt_id,
                            sequence=sequence,
                            kind="associated_method_linked",
                            entity_urn=f"qrh:evidence:associated-method:{association_id}",
                            payload={
                                "associated_relation_id": association_id,
                                "preserved_source_candidate_status": "rejected_non_paper",
                            },
                        )
                self._project_catalog(
                    connection,
                    paper_id=paper_id,
                    item=item,
                    conclusions=conclusions,
                    resource=resource_row,
                )
                sequence += 1
                self._record_event(
                    connection,
                    receipt_id=receipt_id,
                    sequence=sequence,
                    kind="catalog_projected",
                    entity_urn=f"qrh:evidence:paper:{paper_id}:catalog",
                    payload={
                        "resource_mode": resource_mode,
                        "core_conclusion_count": len(conclusions),
                    },
                )
                sequence += 1
                commit_payload: dict[str, object] = {
                    "paper_id": paper_id,
                    "bound_citations": len(bound_ids),
                    "research_relations": len(relation_ids),
                    "associated_relations": len(association_ids),
                    "resource_mode": resource_mode,
                    "result_material_sha256": result_hash,
                }
                if official_abstract_excerpt_id is not None:
                    commit_payload.update(
                        {
                            "official_abstract_excerpt_id": official_abstract_excerpt_id,
                            "official_abstract_sha256": official_abstract_sha256,
                        }
                    )
                commit_event_id = self._record_event(
                    connection,
                    receipt_id=receipt_id,
                    sequence=sequence,
                    kind="application_committed",
                    entity_urn=f"qrh:evidence:canonicalization-receipt:{receipt_id}",
                    payload=commit_payload,
                )
                connection.execute(
                    """
                    INSERT INTO evidence_canonicalization_state(
                        canonicalization_receipt_id,state,revision,source_event_id,updated_at
                    ) VALUES(?,'applied',1,?,?)
                    """,
                    (receipt_id, commit_event_id, utc_now()),
                )
                results.append(
                    CanonicalizationItemResult(
                        receipt_id=receipt_id,
                        item_key=item.item_key,
                        paper_id=paper_id,
                        treatment=item.treatment,
                        resource_mode=resource_mode,
                        bound_citations=len(bound_ids),
                        associated_relations=len(association_ids),
                        created=True,
                    )
                )
        return CanonicalizationApplyResult(manifest_hash, tuple(results))
