from __future__ import annotations

import hashlib
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .ids import citation_id_for_locator, citation_id_for_marker, normalize_identifier


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class CitationOccurrenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    legacy_occurrence_id: str = Field(min_length=1, max_length=128)
    clue_id: str | None = Field(default=None, min_length=1, max_length=128)
    research_urn: str = Field(min_length=3, max_length=1_000)
    archive_release_urn: str = Field(min_length=3, max_length=1_000)
    document_version_urn: str = Field(min_length=3, max_length=1_000)
    source_object_urn: str = Field(min_length=3, max_length=1_000)
    document_sha256: Sha256
    source_path: str = Field(default="unknown", min_length=1, max_length=2_000)
    canonical_path: str = Field(default="unknown", min_length=1, max_length=2_000)
    locator_claim: str = Field(default="line:1", min_length=1, max_length=500)
    locator_kind: Literal[
        "utf8_bytes", "pdf_extracted_page_line", "source_locator_claim"
    ] = "utf8_bytes"
    locator: dict[str, object] = Field(default_factory=dict)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    byte_start: int | None = Field(default=None, ge=0)
    byte_end: int | None = Field(default=None, gt=0)
    raw_marker_text: str
    context_text: str
    occurrence_kind: Literal[
        "strong_identifier",
        "formal_reference",
        "textual_mention",
        "method_or_resource_name",
    ]
    resolution_status: Literal[
        "unresolved", "resolved", "source_only", "conflicted", "rejected_non_paper"
    ]
    status_reason: str = Field(min_length=1, max_length=2_000)
    raw_occurrence_type: str = Field(default="unknown", min_length=1, max_length=200)
    candidate_link_method: str = Field(default="unknown", min_length=1, max_length=300)
    evidence_strength: str = Field(default="unknown", min_length=1, max_length=300)
    identifier_claim: str = Field(default="", max_length=2_000)
    ledger_payload: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end cannot precede line_start")
        if self.locator_kind == "utf8_bytes":
            if self.byte_start is None or self.byte_end is None:
                raise ValueError("UTF-8 citation locator requires a byte span")
            if self.byte_end <= self.byte_start:
                raise ValueError("byte_end must be greater than byte_start")
        elif self.byte_start is not None or self.byte_end is not None:
            raise ValueError("non-byte citation locator cannot claim byte offsets")
        if not self.source_object_urn.endswith(self.document_sha256):
            raise ValueError("source object URN must commit to document SHA-256")
        return self

    @property
    def raw_marker_sha256(self) -> str:
        return hashlib.sha256(self.raw_marker_text.encode("utf-8")).hexdigest()

    @property
    def context_sha256(self) -> str:
        return hashlib.sha256(self.context_text.encode("utf-8")).hexdigest()

    @property
    def citation_id(self) -> str:
        if self.locator_kind == "utf8_bytes":
            assert self.byte_start is not None and self.byte_end is not None
            return citation_id_for_marker(
                self.document_sha256,
                self.byte_start,
                self.byte_end,
                self.raw_marker_text,
            )
        return citation_id_for_locator(
            self.document_sha256,
            self.locator_kind,
            self.locator,
            self.raw_marker_text,
        )

    @property
    def locator_status(self) -> str:
        if self.locator_kind == "utf8_bytes":
            return "valid"
        if self.locator_kind in {"pdf_extracted_page_line", "source_locator_claim"}:
            return "source_only"
        return "unresolved"

    def verify_source_bytes(self, source_bytes: bytes) -> None:
        if self.locator_kind != "utf8_bytes":
            raise ValueError("non-byte citation locator cannot be verified as raw source bytes")
        if hashlib.sha256(source_bytes).hexdigest() != self.document_sha256:
            raise ValueError("citation source bytes do not match the approved document hash")
        marker_bytes = self.raw_marker_text.encode("utf-8")
        assert self.byte_start is not None and self.byte_end is not None
        if source_bytes[self.byte_start : self.byte_end] != marker_bytes:
            raise ValueError("citation UTF-8 byte span does not equal raw_marker_text")
        lines = source_bytes.decode("utf-8").splitlines()
        if self.line_end > len(lines):
            raise ValueError("citation line locator is outside the source document")
        if self.context_text != lines[self.line_start - 1]:
            raise ValueError("citation context does not equal its exact source line")


class StrongIdentifierInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["doi", "arxiv", "pmid", "pmcid", "report", "isbn", "url"]
    raw_value: str = Field(min_length=1, max_length=2_000)
    assertion_status: Literal["claimed", "verified", "conflicted", "rejected"]
    provenance_urn: str = Field(min_length=3, max_length=2_000)

    @property
    def normalized_value(self) -> str:
        return normalize_identifier(self.scheme, self.raw_value)


class FetchAttemptInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requested_url: str = Field(pattern=r"^https?://", max_length=4_000)
    redirect_chain: tuple[str, ...] = ()
    final_url: str | None = Field(default=None, pattern=r"^https?://", max_length=4_000)
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_mime: str | None = Field(default=None, max_length=300)
    response_bytes: int | None = Field(default=None, ge=0)
    response_sha256: Sha256 | None = None
    request_identity_hash: Sha256
    rights_status: Literal[
        "verified_open_license",
        "repository_distribution_only",
        "public_access_unknown_reuse",
        "not_open_access",
        "license_blocked",
        "unknown",
    ]
    legal_basis: str = Field(min_length=1, max_length=4_000)
    result_status: Literal[
        "succeeded",
        "http_failed",
        "network_failed",
        "license_blocked",
        "invalid_content",
        "not_attempted",
    ]
    error_class: str | None = Field(default=None, max_length=200)
    error_detail: str | None = Field(default=None, max_length=4_000)

    @model_validator(mode="after")
    def validate_success_material(self) -> Self:
        complete = (
            self.final_url,
            self.http_status,
            self.response_mime,
            self.response_bytes,
            self.response_sha256,
        )
        if self.result_status == "succeeded":
            if any(value is None for value in complete):
                raise ValueError("successful fetch requires complete response material")
            assert self.http_status is not None
            if not 200 <= self.http_status <= 299:
                raise ValueError("successful fetch requires a 2xx HTTP status")
        return self
