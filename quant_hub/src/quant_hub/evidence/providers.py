from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from pydantic import BaseModel, ConfigDict, Field, model_validator

from quant_hub.platform.workflow import canonical_json

from .ids import normalize_identifier


ProviderName = Literal["crossref", "arxiv"]
ProviderOperation = Literal["identifier_lookup", "metadata_search"]

_ATOM = "{http://www.w3.org/2005/Atom}"
_ARXIV = "{http://arxiv.org/schemas/atom}"
_CROSSREF_MIME_TYPES = {
    "application/json",
}
_ARXIV_MIME_TYPES = {
    "application/atom+xml",
    "application/xml",
    "text/xml",
}
_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "crossref-api-key",
    "crossref-plus-api-token",
    "proxy-authorization",
    "set-cookie",
}


class ProviderContractError(ValueError):
    """Provider request or response violated the frozen adapter contract."""


class StrongIdentifierQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["doi", "arxiv", "pmid", "pmcid", "report", "isbn", "url"]
    raw_value: str = Field(min_length=1, max_length=2_000)
    source_provenance_urn: str = Field(min_length=3, max_length=2_000)

    @property
    def normalized_value(self) -> str:
        return normalize_identifier(self.scheme, self.raw_value)


class ResolutionQuery(BaseModel):
    """A source-bounded query. It is evidence input, not a match decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str | None = Field(default=None, min_length=1, max_length=2_000)
    authors: tuple[str, ...] = ()
    publication_year: int | None = Field(default=None, ge=1400, le=3000)
    identifiers: tuple[StrongIdentifierQuery, ...] = ()

    @model_validator(mode="after")
    def require_search_material(self) -> "ResolutionQuery":
        if self.title is None and not self.identifiers:
            raise ValueError("resolution query requires a title or a strong identifier")
        if any(not author.strip() for author in self.authors):
            raise ValueError("author claims cannot be blank")
        return self

    def snapshot_material(self) -> dict[str, object]:
        return {
            "title": self.title,
            "authors": list(self.authors),
            "publication_year": self.publication_year,
            "identifiers": [
                {
                    "scheme": item.scheme,
                    "raw_value": item.raw_value,
                    "normalized_value": item.normalized_value,
                    "source_provenance_urn": item.source_provenance_urn,
                }
                for item in self.identifiers
            ],
        }


class ProviderRequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderName
    operation: ProviderOperation
    url: str = Field(pattern=r"^https://", max_length=4_000)
    method: Literal["GET"] = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    query_context: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_secrets(self) -> "ProviderRequestSpec":
        sensitive = _SENSITIVE_HEADER_NAMES.intersection(
            name.casefold() for name in self.headers
        )
        if sensitive:
            raise ValueError(f"provider request cannot persist sensitive headers: {sorted(sensitive)}")
        return self

    @property
    def fingerprint(self) -> str:
        material = {
            "provider": self.provider,
            "operation": self.operation,
            "url": self.url,
            "method": self.method,
            "headers": dict(sorted(self.headers.items(), key=lambda item: item[0].casefold())),
            "query_context": self.query_context,
        }
        return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


class ProviderHttpResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    request_url: str = Field(pattern=r"^https://", max_length=4_000)
    final_url: str = Field(pattern=r"^https://", max_length=4_000)
    redirect_chain: tuple[str, ...] = ()
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: bytes = Field(max_length=10_000_000)

    @model_validator(mode="after")
    def require_https_redirects(self) -> "ProviderHttpResponse":
        if any(not value.startswith("https://") for value in self.redirect_chain):
            raise ValueError("provider redirect chains must remain on HTTPS")
        return self

    @property
    def media_type(self) -> str:
        value = next(
            (value for name, value in self.headers.items() if name.casefold() == "content-type"),
            "",
        )
        return value.split(";", 1)[0].strip().casefold()

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


class IdentifierObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["doi", "arxiv"]
    raw_value: str = Field(min_length=1, max_length=2_000)
    normalized_value: str = Field(min_length=1, max_length=2_000)
    verification_status: Literal["provider_verified", "provider_claimed"]


class ResourceOfferObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderName
    resource_kind: Literal["paper_pdf", "supplement", "source_archive"]
    source_kind: Literal["official_repository", "publisher_link", "registry_link"]
    url: str = Field(pattern=r"^https://", max_length=4_000)
    media_type: str = Field(min_length=1, max_length=300)
    rights_hint: Literal[
        "verified_open_license",
        "repository_distribution_only",
        "public_access_unknown_reuse",
        "not_open_access",
        "license_blocked",
        "unknown",
    ]
    license_evidence: dict[str, object] = Field(default_factory=dict)
    provenance_urn: str = Field(min_length=3, max_length=2_000)


class ProviderObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderName
    provider_record_id: str = Field(min_length=1, max_length=2_000)
    provider_rank: int = Field(ge=1)
    provider_score: float | None = None
    record: dict[str, object]
    metadata: dict[str, object]
    identifiers: tuple[IdentifierObservation, ...] = ()
    match_basis: Literal[
        "source_identifier_exact", "metadata_candidate_only", "identifier_mismatch"
    ]
    identity_effect: Literal[
        "strong_identifier_verified", "review_required", "conflicted", "none"
    ]
    rationale: str = Field(min_length=1, max_length=4_000)
    resource_offers: tuple[ResourceOfferObservation, ...] = ()
    provenance_urn: str = Field(min_length=3, max_length=2_000)

    @model_validator(mode="after")
    def require_match_effect_consistency(self) -> "ProviderObservation":
        expected = {
            "source_identifier_exact": "strong_identifier_verified",
            "metadata_candidate_only": "review_required",
            "identifier_mismatch": "conflicted",
        }[self.match_basis]
        if self.identity_effect != expected:
            raise ValueError(
                f"{self.match_basis} observations require identity_effect={expected}"
            )
        return self

    @property
    def record_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.record).encode("utf-8")).hexdigest()


class ProviderParseResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderName
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observations: tuple[ProviderObservation, ...] = ()
    response_provenance_urn: str = Field(min_length=3, max_length=2_000)


class RightsAssessmentProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Literal[
        "approved_for_local_storage", "metadata_only", "review_required", "blocked"
    ]
    rights_status: Literal[
        "verified_open_license",
        "repository_distribution_only",
        "public_access_unknown_reuse",
        "not_open_access",
        "license_blocked",
        "unknown",
    ]
    authority_kind: Literal["deterministic_rights_policy", "human_review"]
    policy_version: str = Field(min_length=1, max_length=300)
    legal_basis: str = Field(min_length=1, max_length=4_000)
    evidence: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_approved_rights_status(self) -> "RightsAssessmentProposal":
        if self.decision == "approved_for_local_storage" and self.rights_status not in {
            "verified_open_license",
            "repository_distribution_only",
        }:
            raise ValueError(
                "local-storage approval requires an explicitly storage-capable rights status"
            )
        return self


@runtime_checkable
class ProviderAdapter(Protocol):
    name: ProviderName

    def plan(self, query: ResolutionQuery) -> tuple[ProviderRequestSpec, ...]: ...

    def parse(
        self, request: ProviderRequestSpec, response: ProviderHttpResponse
    ) -> ProviderParseResult: ...


def _collapse(value: object) -> str:
    return " ".join(str(value or "").split())


def _https_official_url(value: str, *, allowed_hosts: set[str]) -> str | None:
    parsed = urlsplit(value.strip())
    host = (parsed.hostname or "").casefold()
    if host not in allowed_hosts or parsed.scheme.casefold() not in {"http", "https"}:
        return None
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def _first_string(value: object) -> str | None:
    if isinstance(value, list) and value and isinstance(value[0], str):
        result = _collapse(value[0])
        return result or None
    if isinstance(value, str):
        result = _collapse(value)
        return result or None
    return None


def _crossref_date(record: Mapping[str, object]) -> str | None:
    for field in ("published-print", "published-online", "published", "issued", "created"):
        value = record.get(field)
        if not isinstance(value, Mapping):
            continue
        parts = value.get("date-parts")
        if not isinstance(parts, list) or not parts or not isinstance(parts[0], list):
            continue
        values = parts[0]
        if not values:
            continue
        try:
            year = int(values[0])
            month = int(values[1]) if len(values) > 1 else 1
            day = int(values[2]) if len(values) > 2 else 1
        except (TypeError, ValueError):
            continue
        if 1400 <= year <= 3000 and 1 <= month <= 12 and 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"
    return None


class CrossrefAdapter:
    """Crossref v1 metadata adapter. Search scores never become identity decisions."""

    name: ProviderName = "crossref"
    # Match the official endpoint persisted by the reviewed exact-DOI audit.
    # Crossref's public REST route is /works; inventing a /v1 request URL would
    # falsely rebind cached response bytes to a request that was never issued.
    base_url = "https://api.crossref.org"

    def __init__(self, *, mailto: str | None = None, max_results: int = 5):
        if not 1 <= max_results <= 20:
            raise ValueError("Crossref candidate window must be between 1 and 20")
        self.mailto = mailto.strip() if mailto else None
        self.max_results = max_results

    def plan(self, query: ResolutionQuery) -> tuple[ProviderRequestSpec, ...]:
        requests: list[ProviderRequestSpec] = []
        headers = {
            "Accept": "application/json",
            "User-Agent": "QuantResearchHub/0.1 EvidenceResolver",
        }
        for identifier in query.identifiers:
            if identifier.scheme != "doi":
                continue
            normalized = identifier.normalized_value
            params = f"?{urlencode({'mailto': self.mailto})}" if self.mailto else ""
            requests.append(
                ProviderRequestSpec(
                    provider="crossref",
                    operation="identifier_lookup",
                    url=f"{self.base_url}/works/{quote(normalized, safe='')}{params}",
                    headers=headers,
                    query_context={
                        "explicit_identifier": {
                            "scheme": "doi",
                            "normalized_value": normalized,
                            "source_provenance_urn": identifier.source_provenance_urn,
                        }
                    },
                )
            )
        if query.title:
            bibliographic = " | ".join(
                part
                for part in (
                    query.title,
                    "; ".join(query.authors),
                    str(query.publication_year) if query.publication_year else "",
                )
                if part
            )
            params: dict[str, object] = {
                "query.bibliographic": bibliographic,
                "rows": self.max_results,
            }
            if self.mailto:
                params["mailto"] = self.mailto
            requests.append(
                ProviderRequestSpec(
                    provider="crossref",
                    operation="metadata_search",
                    url=f"{self.base_url}/works?{urlencode(params)}",
                    headers=headers,
                    query_context={
                        "title": query.title,
                        "authors": list(query.authors),
                        "publication_year": query.publication_year,
                        "candidate_window": self.max_results,
                        "identity_rule": "metadata_results_require_explicit_review",
                    },
                )
            )
        return tuple(requests)

    def parse(
        self, request: ProviderRequestSpec, response: ProviderHttpResponse
    ) -> ProviderParseResult:
        if request.provider != self.name or response.request_url != request.url:
            raise ProviderContractError("Crossref response does not match its frozen request")
        if not 200 <= response.status_code <= 299:
            raise ProviderContractError("Crossref parser only accepts successful transport results")
        if response.media_type not in _CROSSREF_MIME_TYPES:
            raise ProviderContractError(f"unexpected Crossref response MIME: {response.media_type!r}")
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderContractError("Crossref response is not UTF-8 JSON") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("message"), dict):
            raise ProviderContractError("Crossref response has no message object")
        message = payload["message"]
        if request.operation == "identifier_lookup":
            records = [message]
        else:
            items = message.get("items")
            if not isinstance(items, list):
                raise ProviderContractError("Crossref search response has no items array")
            records = items
        observations = tuple(
            self._observation(request, response, record, rank)
            for rank, record in enumerate(records, start=1)
            if isinstance(record, dict)
        )
        provenance = f"qrh:evidence:provider-response:crossref:sha256:{response.body_sha256}"
        return ProviderParseResult(
            provider="crossref",
            request_fingerprint=request.fingerprint,
            response_sha256=response.body_sha256,
            observations=observations,
            response_provenance_urn=provenance,
        )

    def _observation(
        self,
        request: ProviderRequestSpec,
        response: ProviderHttpResponse,
        raw: dict[str, Any],
        rank: int,
    ) -> ProviderObservation:
        raw_doi = str(raw.get("DOI") or "").strip()
        doi: str | None = None
        if raw_doi:
            try:
                doi = normalize_identifier("doi", raw_doi)
            except ValueError:
                doi = None
        authors: list[dict[str, object]] = []
        for item in raw.get("author") or []:
            if not isinstance(item, dict):
                continue
            name = _collapse(" ".join(str(item.get(key) or "") for key in ("given", "family")))
            if not name:
                continue
            authors.append(
                {
                    "name": name,
                    "orcid": str(item.get("ORCID") or "") or None,
                    "affiliations": [
                        _collapse(value.get("name"))
                        for value in item.get("affiliation") or []
                        if isinstance(value, dict) and _collapse(value.get("name"))
                    ],
                }
            )
        licenses = [
            {
                key: value
                for key, value in item.items()
                if key in {"URL", "start", "delay-in-days", "content-version"}
            }
            for item in raw.get("license") or []
            if isinstance(item, dict)
        ]
        links = [
            {
                key: value
                for key, value in item.items()
                if key in {"URL", "content-type", "content-version", "intended-application"}
            }
            for item in raw.get("link") or []
            if isinstance(item, dict)
        ]
        title = _first_string(raw.get("title"))
        metadata: dict[str, object] = {
            "title": title,
            "authors": authors,
            "publication_date": _crossref_date(raw),
            "container_title": _first_string(raw.get("container-title")),
            "publisher": _collapse(raw.get("publisher")) or None,
            "type": _collapse(raw.get("type")) or None,
            "url": str(raw.get("URL") or "") or None,
            "licenses": licenses,
        }
        # Crossref abstracts can remain under publisher/author copyright. The adapter
        # commits to the response hash but intentionally excludes abstract text here.
        record = {
            "DOI": doi,
            "title": title,
            "author": authors,
            "publication_date": metadata["publication_date"],
            "container_title": metadata["container_title"],
            "publisher": metadata["publisher"],
            "type": metadata["type"],
            "URL": metadata["url"],
            "license": licenses,
            "link": links,
            "score": raw.get("score"),
            "abstract_omitted_by_policy": "crossref_abstract_copyright_boundary",
        }
        explicit = request.query_context.get("explicit_identifier")
        if isinstance(explicit, dict):
            expected = str(explicit.get("normalized_value") or "")
            if doi == expected:
                match_basis = "source_identifier_exact"
                identity_effect = "strong_identifier_verified"
                rationale = "Crossref DOI registry record exactly matches the source DOI claim; no paper entity was created."
            else:
                match_basis = "identifier_mismatch"
                identity_effect = "conflicted"
                rationale = "Crossref DOI registry response differs from the source DOI claim."
        else:
            match_basis = "metadata_candidate_only"
            identity_effect = "review_required"
            rationale = "Crossref bibliographic search result is observational only; rank and score cannot select identity."
        identifiers = (
            (
                IdentifierObservation(
                    scheme="doi",
                    raw_value=raw_doi,
                    normalized_value=doi,
                    verification_status="provider_verified",
                ),
            )
            if doi
            else ()
        )
        provenance = f"qrh:evidence:provider-response:crossref:sha256:{response.body_sha256}:rank:{rank}"
        offer_claims: dict[tuple[str, str], list[dict[str, object]]] = {}
        for item in links:
            url = str(item.get("URL") or "")
            parsed = urlsplit(url)
            if parsed.scheme.casefold() != "https" or not parsed.netloc:
                continue
            media_type = str(item.get("content-type") or "application/octet-stream")
            kind = "paper_pdf" if media_type.casefold() == "application/pdf" else "supplement"
            offer_claims.setdefault((kind, url), []).append(
                {
                    "content_type": media_type,
                    "content_version": item.get("content-version"),
                    "intended_application": item.get("intended-application"),
                }
            )
        offers: list[ResourceOfferObservation] = []
        for (kind, url), claims in sorted(offer_claims.items()):
            media_types = {str(value["content_type"]) for value in claims}
            media_type = (
                next(iter(media_types))
                if len(media_types) == 1
                else "application/octet-stream"
            )
            offers.append(
                ResourceOfferObservation(
                    provider="crossref",
                    resource_kind=kind,
                    source_kind="registry_link",
                    url=url,
                    media_type=media_type,
                    rights_hint="unknown",
                    license_evidence={
                        "crossref_licenses": licenses,
                        "crossref_link_claims": claims,
                        "warning": "Crossref states that a full-text URL does not guarantee access or reuse rights.",
                    },
                    provenance_urn=provenance,
                )
            )
        record_id = doi or f"sha256:{hashlib.sha256(canonical_json(record).encode('utf-8')).hexdigest()}"
        return ProviderObservation(
            provider="crossref",
            provider_record_id=record_id,
            provider_rank=rank,
            provider_score=float(raw["score"]) if isinstance(raw.get("score"), (int, float)) else None,
            record=record,
            metadata=metadata,
            identifiers=identifiers,
            match_basis=match_basis,
            identity_effect=identity_effect,
            rationale=rationale,
            resource_offers=tuple(offers),
            provenance_urn=provenance,
        )


def _xml_text(element: ET.Element, path: str) -> str | None:
    child = element.find(path)
    if child is None:
        return None
    value = _collapse(child.text)
    return value or None


def _normalized_open_license_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value.strip())
    host = (parsed.hostname or "").casefold()
    if host not in {"creativecommons.org", "www.creativecommons.org"}:
        return None
    path = parsed.path.casefold()
    if not (path.startswith("/licenses/") or path.startswith("/publicdomain/")):
        return None
    return urlunsplit(("https", "creativecommons.org", parsed.path, parsed.query, parsed.fragment))


class ArxivAdapter:
    """Official arXiv Atom adapter. Search results always require review."""

    name: ProviderName = "arxiv"
    base_url = "https://export.arxiv.org/api/query"

    def __init__(self, *, max_results: int = 5):
        if not 1 <= max_results <= 20:
            raise ValueError("arXiv candidate window must be between 1 and 20")
        self.max_results = max_results

    def plan(self, query: ResolutionQuery) -> tuple[ProviderRequestSpec, ...]:
        headers = {
            "Accept": "application/atom+xml",
            "User-Agent": "QuantResearchHub/0.1 EvidenceResolver",
        }
        requests: list[ProviderRequestSpec] = []
        for identifier in query.identifiers:
            if identifier.scheme != "arxiv":
                continue
            normalized = identifier.normalized_value
            # The reviewed official artifacts were fetched with the minimal
            # exact-ID request.  `id_list` already bounds this lookup to one ID.
            params = urlencode({"id_list": normalized})
            requests.append(
                ProviderRequestSpec(
                    provider="arxiv",
                    operation="identifier_lookup",
                    url=f"{self.base_url}?{params}",
                    headers=headers,
                    query_context={
                        "explicit_identifier": {
                            "scheme": "arxiv",
                            "normalized_value": normalized,
                            "source_provenance_urn": identifier.source_provenance_urn,
                        }
                    },
                )
            )
        if query.title:
            params = urlencode(
                {
                    "search_query": f'ti:"{query.title}"',
                    "start": 0,
                    "max_results": self.max_results,
                    "sortBy": "relevance",
                    "sortOrder": "descending",
                }
            )
            requests.append(
                ProviderRequestSpec(
                    provider="arxiv",
                    operation="metadata_search",
                    url=f"{self.base_url}?{params}",
                    headers=headers,
                    query_context={
                        "title": query.title,
                        "authors": list(query.authors),
                        "publication_year": query.publication_year,
                        "candidate_window": self.max_results,
                        "identity_rule": "metadata_results_require_explicit_review",
                    },
                )
            )
        return tuple(requests)

    def parse(
        self, request: ProviderRequestSpec, response: ProviderHttpResponse
    ) -> ProviderParseResult:
        if request.provider != self.name or response.request_url != request.url:
            raise ProviderContractError("arXiv response does not match its frozen request")
        if not 200 <= response.status_code <= 299:
            raise ProviderContractError("arXiv parser only accepts successful transport results")
        if response.media_type not in _ARXIV_MIME_TYPES:
            raise ProviderContractError(f"unexpected arXiv response MIME: {response.media_type!r}")
        if b"<!DOCTYPE" in response.body.upper() or b"<!ENTITY" in response.body.upper():
            raise ProviderContractError("arXiv Atom response contains a forbidden entity declaration")
        try:
            root = ET.fromstring(response.body)
        except ET.ParseError as error:
            raise ProviderContractError("arXiv response is not valid Atom XML") from error
        if root.tag != f"{_ATOM}feed":
            raise ProviderContractError("arXiv response root is not an Atom feed")
        observations = tuple(
            self._observation(request, response, entry, rank)
            for rank, entry in enumerate(root.findall(f"{_ATOM}entry"), start=1)
        )
        provenance = f"qrh:evidence:provider-response:arxiv:sha256:{response.body_sha256}"
        return ProviderParseResult(
            provider="arxiv",
            request_fingerprint=request.fingerprint,
            response_sha256=response.body_sha256,
            observations=observations,
            response_provenance_urn=provenance,
        )

    def _observation(
        self,
        request: ProviderRequestSpec,
        response: ProviderHttpResponse,
        entry: ET.Element,
        rank: int,
    ) -> ProviderObservation:
        entry_url = _xml_text(entry, f"{_ATOM}id") or ""
        try:
            arxiv_id = normalize_identifier("arxiv", entry_url)
        except ValueError as error:
            raise ProviderContractError("arXiv Atom entry has no canonical identifier") from error
        title = _xml_text(entry, f"{_ATOM}title")
        summary = _xml_text(entry, f"{_ATOM}summary")
        published = _xml_text(entry, f"{_ATOM}published")
        updated = _xml_text(entry, f"{_ATOM}updated")
        authors = [
            name
            for author in entry.findall(f"{_ATOM}author")
            if (name := _xml_text(author, f"{_ATOM}name"))
        ]
        categories = [
            str(item.attrib.get("term") or "")
            for item in entry.findall(f"{_ATOM}category")
            if str(item.attrib.get("term") or "")
        ]
        raw_doi = _xml_text(entry, f"{_ARXIV}doi")
        doi: str | None = None
        if raw_doi:
            try:
                doi = normalize_identifier("doi", raw_doi)
            except ValueError:
                doi = None
        raw_license = _xml_text(entry, f"{_ARXIV}license")
        open_license = _normalized_open_license_url(raw_license)
        links: list[dict[str, str | None]] = []
        for link in entry.findall(f"{_ATOM}link"):
            links.append(
                {
                    "href": str(link.attrib.get("href") or ""),
                    "rel": str(link.attrib.get("rel") or "") or None,
                    "type": str(link.attrib.get("type") or "") or None,
                    "title": str(link.attrib.get("title") or "") or None,
                }
            )
        metadata: dict[str, object] = {
            "title": title,
            "abstract": summary,
            "authors": authors,
            "publication_date": published,
            "updated_at": updated,
            "categories": categories,
            "doi": doi,
            "journal_reference": _xml_text(entry, f"{_ARXIV}journal_ref"),
            "comment": _xml_text(entry, f"{_ARXIV}comment"),
            "license_url": open_license or raw_license,
            "landing_url": f"https://arxiv.org/abs/{arxiv_id}",
        }
        record = {
            "arxiv_id": arxiv_id,
            **metadata,
            "links": links,
            "raw_license_url": raw_license,
        }
        explicit = request.query_context.get("explicit_identifier")
        if isinstance(explicit, dict):
            expected = str(explicit.get("normalized_value") or "")
            if arxiv_id == expected:
                match_basis = "source_identifier_exact"
                identity_effect = "strong_identifier_verified"
                rationale = "Official arXiv Atom metadata exactly matches the source arXiv identifier; no paper entity was created."
            else:
                match_basis = "identifier_mismatch"
                identity_effect = "conflicted"
                rationale = "Official arXiv Atom entry differs from the source arXiv identifier."
        else:
            match_basis = "metadata_candidate_only"
            identity_effect = "review_required"
            rationale = "arXiv title-search result is observational only; relevance order cannot select identity."
        identifiers: list[IdentifierObservation] = [
            IdentifierObservation(
                scheme="arxiv",
                raw_value=entry_url,
                normalized_value=arxiv_id,
                verification_status="provider_verified",
            )
        ]
        if doi:
            identifiers.append(
                IdentifierObservation(
                    scheme="doi",
                    raw_value=raw_doi or doi,
                    normalized_value=doi,
                    verification_status="provider_claimed",
                )
            )
        provenance = f"qrh:evidence:provider-response:arxiv:sha256:{response.body_sha256}:rank:{rank}"
        offers: list[ResourceOfferObservation] = []
        for link in links:
            media_type = str(link.get("type") or "")
            title_attr = str(link.get("title") or "").casefold()
            if media_type.casefold() != "application/pdf" and title_attr != "pdf":
                continue
            official_url = _https_official_url(
                str(link.get("href") or ""),
                allowed_hosts={"arxiv.org", "www.arxiv.org", "export.arxiv.org"},
            )
            if official_url is None:
                continue
            offers.append(
                ResourceOfferObservation(
                    provider="arxiv",
                    resource_kind="paper_pdf",
                    source_kind="official_repository",
                    url=official_url,
                    media_type="application/pdf",
                    rights_hint="verified_open_license" if open_license else "unknown",
                    license_evidence={
                        "raw_license_url": raw_license,
                        "normalized_open_license_url": open_license,
                        "arxiv_license_information": "https://info.arxiv.org/help/license/index.html",
                    },
                    provenance_urn=provenance,
                )
            )
        return ProviderObservation(
            provider="arxiv",
            provider_record_id=arxiv_id,
            provider_rank=rank,
            provider_score=None,
            record=record,
            metadata=metadata,
            identifiers=tuple(identifiers),
            match_basis=match_basis,
            identity_effect=identity_effect,
            rationale=rationale,
            resource_offers=tuple(offers),
            provenance_urn=provenance,
        )


class ConservativeRightsPolicy:
    """Only a per-work, recognized open license can auto-authorize local storage."""

    version = "qrh-evidence-rights-policy/v1"

    def assess(self, offer: ResourceOfferObservation) -> RightsAssessmentProposal:
        license_url = _normalized_open_license_url(
            str(offer.license_evidence.get("normalized_open_license_url") or "") or None
        )
        if (
            offer.provider == "arxiv"
            and offer.source_kind == "official_repository"
            and offer.rights_hint == "verified_open_license"
            and license_url is not None
        ):
            return RightsAssessmentProposal(
                decision="approved_for_local_storage",
                rights_status="verified_open_license",
                authority_kind="deterministic_rights_policy",
                policy_version=self.version,
                legal_basis=f"Per-work open-license URL observed in official arXiv metadata: {license_url}",
                evidence={
                    "license_url": license_url,
                    "resource_url": offer.url,
                    "provider": offer.provider,
                    "policy_rule": "official_arxiv_resource_with_recognized_per_work_open_license",
                },
            )
        return RightsAssessmentProposal(
            decision="review_required",
            rights_status=offer.rights_hint,
            authority_kind="deterministic_rights_policy",
            policy_version=self.version,
            legal_basis=(
                "The provider observation does not prove a per-work reuse right that this "
                "policy can safely translate into local-storage authorization."
            ),
            evidence={
                "resource_url": offer.url,
                "provider": offer.provider,
                "rights_hint": offer.rights_hint,
                "license_evidence": offer.license_evidence,
                "required_next_step": "explicit_human_rights_review",
            },
        )
