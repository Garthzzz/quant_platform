from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence
import xml.etree.ElementTree as ET

from quant_hub.config import Settings

from .canonicalization import (
    CanonicalizationEligibilityError,
    MethodOriginCandidateInput,
    ReviewedAuthor,
    ReviewedCategoryAssertion,
    ReviewedCanonicalizationItem,
    ReviewedCanonicalizationManifest,
    ReviewedConclusion,
    ReviewedExternalLink,
    ReviewedExcerpt,
    ReviewedFulltextLocator,
    ReviewedInstitutionResolution,
    ReviewedMetadata,
    ReviewedReadingConclusion,
    ReviewedReadingResult,
    ReviewedResource,
    ReviewedSourceCategory,
    ReviewedVenueClaim,
)
from .database import evidence_connection
from .ids import normalize_identifier


BROAD_CATEGORY_MAPPING_POLICY = "qrh-reviewed-broad-domain-map/v1"
ARXIV_ATOM_SUMMARY_NORMALIZATION = (
    "xml.etree.ElementTree:atom.entry.summary:itertext:"
    "regex-whitespace-collapse:strip:utf8/v1"
)
CROSSREF_DEPOSIT_ABSTRACT_NORMALIZATION = (
    "html.parser.HTMLParser:crossref.message.abstract:jats-text:"
    "leading-abstract-label-strip:regex-whitespace-collapse:strip:utf8/v1"
)
_ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
DEFAULT_CROSSREF_RECONCILIATION_DENYLIST: dict[str, str] = {
    "P095": (
        "version-family ambiguity: the 2011 local author/title/year clue does not "
        "distinguish NBER Working Paper 16972 from the Journal of Finance version"
    )
}


def normalize_arxiv_atom_summary(payload: bytes) -> str:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise ValueError("official arXiv Atom artifact is not valid XML") from error
    entries = root.findall(f"{{{_ATOM_NAMESPACE}}}entry")
    if len(entries) != 1:
        raise ValueError(
            f"official arXiv Atom artifact must contain one entry, found {len(entries)}"
        )
    summaries = entries[0].findall(f"{{{_ATOM_NAMESPACE}}}summary")
    if len(summaries) != 1:
        raise ValueError(
            "official arXiv Atom entry must contain exactly one summary"
        )
    text = re.sub(r"\s+", " ", "".join(summaries[0].itertext())).strip()
    if not text:
        raise ValueError("official arXiv Atom summary is empty")
    return text


class _CrossrefJatsTextExtractor(HTMLParser):
    """从 Crossref deposit 的 JATS 片段抽取可核验纯文本。

    Crossref 的 ``message.abstract`` 通常是 XML/JATS 片段，但经常使用没有在
    片段内声明的 ``jats:`` 前缀，不能把它当作完整 XML 文档解析。HTMLParser
    不访问网络，也不解释外部实体；这里只保留文本节点，并在块级标签边界
    插入空格，防止相邻段落粘连。
    """

    _BLOCK_TAGS = {
        "jats:p",
        "p",
        "jats:title",
        "title",
        "jats:sec",
        "sec",
        "jats:list-item",
        "list-item",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        del attrs
        if tag.casefold() in self._BLOCK_TAGS:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in self._BLOCK_TAGS:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def normalize_crossref_deposit_abstract(value: object) -> str:
    """规范化出版方提交给 Crossref 的官方摘要字段，不生成或改写内容。"""

    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Crossref deposit abstract is empty")
    parser = _CrossrefJatsTextExtractor()
    parser.feed(raw)
    parser.close()
    text = re.sub(r"\s+", " ", "".join(parser.parts)).strip()
    if re.match(r"^abstract(?:\s*[:.\-])?\s+", text, flags=re.IGNORECASE):
        text = re.sub(
            r"^abstract(?:\s*[:.\-])?\s+", "", text, count=1, flags=re.IGNORECASE
        )
    if not text:
        raise ValueError("Crossref deposit abstract has no text nodes")
    return text


def _reviewed_artifact_path(root: Path, value: object, *, label: str) -> Path:
    boundary = root.resolve(strict=True)
    path = Path(str(value))
    resolved = (path if path.is_absolute() else boundary / path).resolve(strict=True)
    if not resolved.is_relative_to(boundary) or not resolved.is_file():
        raise ValueError(f"{label} escapes its reviewed material package")
    return resolved


def _workspace_relative_source_path(path: Path) -> str:
    resolved = path.resolve(strict=True)
    for candidate in resolved.parents:
        project_state = candidate / "project_state"
        if project_state.is_dir() and resolved.is_relative_to(project_state):
            return resolved.relative_to(candidate).as_posix()
    raise ValueError(f"reviewed source is not inside workspace project_state: {resolved}")


def reviewed_arxiv_official_abstract_excerpt(
    materials_root: Path,
    material: Mapping[str, object],
) -> ReviewedExcerpt:
    artifacts = material.get("artifacts")
    requests = material.get("requests")
    official = material.get("official_metadata")
    if not isinstance(artifacts, Mapping) or not isinstance(
        requests, Mapping
    ) or not isinstance(official, Mapping):
        raise ValueError("reviewed arXiv material lacks artifacts/requests/metadata")

    atom_path = _reviewed_artifact_path(
        materials_root, artifacts.get("atom"), label="arXiv Atom artifact"
    )
    request_path = _reviewed_artifact_path(
        materials_root, requests.get("atom"), label="arXiv Atom request receipt"
    )
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if not isinstance(request, dict):
        raise ValueError("arXiv Atom request receipt is not an object")
    receipt_body = _reviewed_artifact_path(
        materials_root,
        request.get("body_path"),
        label="arXiv Atom receipt body",
    )
    if receipt_body != atom_path:
        raise ValueError("arXiv Atom manifest and request receipt select different bodies")
    atom_payload = atom_path.read_bytes()
    atom_sha256 = hashlib.sha256(atom_payload).hexdigest()
    if (
        request.get("successful") is not True
        or int(request.get("http_status") or 0) != 200
        or request.get("sha256") != atom_sha256
        or int(request.get("bytes") or -1) != len(atom_payload)
    ):
        raise ValueError("arXiv Atom request receipt does not bind the source bytes")
    normalized_summary = normalize_arxiv_atom_summary(atom_payload)
    if str(official.get("summary") or "") != normalized_summary:
        raise ValueError("official metadata summary differs from the exact Atom summary")

    abstract_page = _reviewed_artifact_path(
        materials_root,
        artifacts.get("abstract_page"),
        label="arXiv abstract-page corroboration",
    )
    abstract_payload = abstract_page.read_bytes()
    abstract_sha256 = hashlib.sha256(abstract_payload).hexdigest()
    expected_abstract_sha256 = abstract_page.stem.rsplit("_", 1)[-1]
    if abstract_sha256 != expected_abstract_sha256:
        raise ValueError("arXiv abstract-page artifact filename hash is stale")

    arxiv_id = normalize_identifier("arxiv", str(official.get("arxiv_id") or ""))
    source_path = _workspace_relative_source_path(atom_path)
    corroboration_path = _workspace_relative_source_path(abstract_page)
    source_url = str(request.get("final_url") or request.get("request_url") or "")
    if not source_url.startswith("https://"):
        raise ValueError("official arXiv Atom receipt lacks an HTTPS source URL")
    excerpt_sha256 = hashlib.sha256(normalized_summary.encode("utf-8")).hexdigest()
    return ReviewedExcerpt(
        text=normalized_summary,
        page_sha256=abstract_sha256,
        locator={
            "source_kind": "official_arxiv_atom_summary",
            "source_path": source_path,
            "source_file_sha256": atom_sha256,
            "source_file_bytes": len(atom_payload),
            "source_url": source_url,
            "field": "atom.entry.summary",
            "normalization_contract": ARXIV_ATOM_SUMMARY_NORMALIZATION,
            "normalized_excerpt_sha256": excerpt_sha256,
            "normalized_excerpt_bytes": len(normalized_summary.encode("utf-8")),
            "identifier_scheme": "arxiv",
            "normalized_identifier": arxiv_id,
            "title": str(official.get("title") or ""),
            "corroboration": {
                "source_kind": "official_arxiv_abstract_page",
                "source_path": corroboration_path,
                "source_file_sha256": abstract_sha256,
                "source_file_bytes": len(abstract_payload),
                "source_url": str(
                    (official.get("official_urls") or {}).get("abstract") or ""
                ),
            },
        },
        provenance_urn=(
            f"qrh:evidence:arxiv-atom:{arxiv_id}:sha256:{atom_sha256}"
        ),
    )


def _crossref_reconciliation_allows(
    source_id: str,
    overrides: Mapping[str, Mapping[str, str]] | None,
) -> bool:
    override = (overrides or {}).get(source_id)
    if override is not None:
        decision = str(override.get("decision") or "").strip().casefold()
        rationale = str(override.get("rationale") or "").strip()
        authority = str(override.get("authority_kind") or "").strip()
        if decision not in {"allow", "deny"} or not rationale:
            raise ValueError(
                f"{source_id}: reconciliation override requires allow/deny and rationale"
            )
        if decision == "allow" and source_id in DEFAULT_CROSSREF_RECONCILIATION_DENYLIST:
            if authority != "independent_verifier":
                raise ValueError(
                    f"{source_id}: built-in ambiguity deny requires independent_verifier authority"
                )
        return decision == "allow"
    return source_id not in DEFAULT_CROSSREF_RECONCILIATION_DENYLIST


def _normalized_words(*values: object) -> str:
    return " ".join(
        re.sub(r"[^a-z0-9.+-]+", " ", str(value).casefold()).strip()
        for value in values
        if value
    )


def _broad_categories(
    *, source_system: str, source_codes: Iterable[str], title: str, venue: str = ""
) -> tuple[str, ...]:
    """Conservative deterministic map; unmatched records stay explicitly unclassified."""

    codes = tuple(str(value).strip().casefold() for value in source_codes if str(value).strip())
    material = _normalized_words(title, venue, *codes)
    mapped: list[str] = []

    if any(code.startswith("q-fin") for code in codes) or re.search(
        r"\b(asset pricing|portfolio|financial market|stock return|trading|market microstructure|quantitative finance|option pricing)\b",
        material,
    ):
        mapped.append("量化金融")

    arxiv_ml = any(
        code in {"cs.lg", "stat.ml", "cs.ai", "cs.ne", "cs.cv", "cs.cl"}
        for code in codes
    )
    crossref_ml = source_system == "crossref" and re.search(
        r"\b(machine learning|deep learning|neural networks?|representation learning|generalization|overfitting|classification|transformers?|dropout)\b",
        material,
    )
    if arxiv_ml or crossref_ml:
        mapped.append("机器学习")

    math_stat = any(
        code.startswith("math.")
        or (code.startswith("stat.") and code != "stat.ml")
        for code in codes
    ) or (
        source_system == "crossref"
        and bool(
            re.search(
                r"\b(probability|stochastic process|statistical inference|time series|hypothesis testing|mathematical statistics)\b",
                material,
            )
        )
    )
    if math_stat:
        mapped.append("数学与统计")

    if not mapped:
        mapped.append("其他/待分类")
    return tuple(dict.fromkeys(mapped))


def _crossref_exact_source(
    row: Mapping[str, object],
) -> tuple[dict[str, object], Path, bytes, str, str]:
    verification = row.get("direct_doi_verification") or {}
    if not isinstance(verification, Mapping):
        return {}, Path(), b"", "", ""
    evidence = verification.get("raw_body_evidence") or {}
    if not isinstance(evidence, Mapping):
        return {}, Path(), b"", "", ""
    body_path = str(evidence.get("body_path") or "")
    expected_hash = str(evidence.get("sha256") or "")
    if not body_path or len(expected_hash) != 64:
        return {}, Path(), b"", "", ""
    source_path = Path(body_path).resolve(strict=True)
    payload = source_path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected_hash:
        raise ValueError(f"Crossref exact body hash mismatch: {body_path}")
    if (
        evidence.get("byte_for_byte_official_response") is not True
        or int(evidence.get("bytes") or -1) != len(payload)
        or str(verification.get("response_sha256") or "") != expected_hash
        or int(verification.get("http_status") or 0) != 200
    ):
        raise ValueError(f"Crossref exact body receipt mismatch: {body_path}")
    decoded = json.loads(payload.decode("utf-8"))
    message = decoded.get("message") if isinstance(decoded, dict) else None
    if not isinstance(message, dict):
        raise ValueError(f"Crossref exact body has no message object: {body_path}")
    endpoint = str(verification.get("endpoint") or "")
    if not endpoint.startswith("https://api.crossref.org/works/"):
        raise ValueError(f"Crossref exact body has no official HTTPS endpoint: {body_path}")
    return message, source_path, payload, expected_hash, endpoint


def _crossref_exact_message(row: Mapping[str, object]) -> dict[str, object]:
    return _crossref_exact_source(row)[0]


def reviewed_crossref_official_abstract_excerpt(
    row: Mapping[str, object],
) -> ReviewedExcerpt | None:
    """从逐字节绑定的 Crossref DOI 响应构造官方摘要证据。

    缺少 ``message.abstract`` 时返回 ``None``；存在字段时必须通过响应哈希、
    字节数、HTTP 状态、官方 endpoint、DOI 与标题校验。该 excerpt 是来源主张，
    不自动生成或提升为论文全文核心结论。
    """

    message, source_path, payload, source_sha256, endpoint = _crossref_exact_source(
        row
    )
    raw_abstract = message.get("abstract")
    if not isinstance(raw_abstract, str) or not raw_abstract.strip():
        return None
    doi = normalize_identifier("doi", str(message.get("DOI") or ""))
    selected_doi = normalize_identifier("doi", str(row.get("selected_doi") or ""))
    if doi != selected_doi:
        raise ValueError("Crossref deposit abstract DOI differs from reviewed selection")
    titles = message.get("title")
    if not isinstance(titles, list) or not titles or not str(titles[0]).strip():
        raise ValueError("Crossref deposit abstract has no official title binding")
    title = str(titles[0]).strip()
    normalized = normalize_crossref_deposit_abstract(raw_abstract)
    excerpt_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return ReviewedExcerpt(
        text=normalized,
        page_sha256=source_sha256,
        locator={
            "source_kind": "official_crossref_deposit_abstract",
            "source_path": _workspace_relative_source_path(source_path),
            "source_file_sha256": source_sha256,
            "source_file_bytes": len(payload),
            "source_url": endpoint,
            "field": "crossref.message.abstract",
            "normalization_contract": CROSSREF_DEPOSIT_ABSTRACT_NORMALIZATION,
            "normalized_excerpt_sha256": excerpt_sha256,
            "normalized_excerpt_bytes": len(normalized.encode("utf-8")),
            "identifier_scheme": "doi",
            "normalized_identifier": doi,
            "title": title,
            "fact_boundary": "publisher_deposited_source_claim_not_fulltext_review",
        },
        provenance_urn=(
            f"qrh:evidence:crossref-deposit:{doi}:abstract:sha256:{source_sha256}"
        ),
    )


def _jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: JSONL row must be an object")
        rows.append(value)
    return rows


def _path_tuple(value: Path | Sequence[Path]) -> tuple[Path, ...]:
    if isinstance(value, Path):
        return (value,)
    return tuple(value)


def _reading_fact_boundary(value: object, *, path: Path) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value.strip():
        return {"statement": value.strip()}
    raise ValueError(f"{path}: reading fact_boundary must be an object or non-empty string")


def method_origin_inputs_from_reviewed_manifest(
    path: Path,
    *,
    include_source_candidates: frozenset[str] | None = None,
) -> tuple[MethodOriginCandidateInput, ...]:
    """Consume the frozen derivation contract instead of reconstructing it implicitly."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "qrh-method-origin-candidate-input/v1":
        raise ValueError(f"{path}: unsupported method-origin input schema")
    rows = payload.get("items")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: method-origin input has no items array")
    output: list[MethodOriginCandidateInput] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"{path}: method-origin input item must be an object")
        original = str(row.get("original_source_candidate_id") or "")
        derived = str(row.get("derived_source_candidate_id") or "")
        if include_source_candidates is not None and not (
            original in include_source_candidates or derived in include_source_candidates
        ):
            continue
        output.append(MethodOriginCandidateInput.model_validate(row))
    return tuple(output)


def _identity_for_source(
    settings: Settings,
    *,
    source_candidate_id: str,
    scheme: str,
    normalized_identifier: str,
) -> tuple[str, str]:
    with evidence_connection(settings) as connection:
        rows = connection.execute(
            """
            SELECT resolution.resolution_case_id,decision.identity_decision_id,
                   decision.identifier_scheme,decision.normalized_identifier
            FROM paper_clue AS clue
            JOIN paper_clue_candidate AS link USING(clue_id)
            JOIN evidence_resolution_case AS resolution USING(candidate_id)
            JOIN evidence_resolution_state AS state USING(resolution_case_id)
            JOIN evidence_identity_decision AS decision USING(resolution_case_id)
            WHERE clue.source_candidate_id=?
              AND state.state='identifier_verified'
              AND decision.decision_kind='accept_verified_identifier'
            ORDER BY decision.decided_at DESC,decision.identity_decision_id DESC
            """,
            (source_candidate_id,),
        ).fetchall()
    exact = [
        row
        for row in rows
        if row["identifier_scheme"] == scheme
        and row["normalized_identifier"] == normalized_identifier
    ]
    if len(exact) != 1:
        raise CanonicalizationEligibilityError(
            f"{source_candidate_id}: expected one identifier_verified {scheme}:{normalized_identifier} decision, found {len(exact)}"
        )
    return str(exact[0]["resolution_case_id"]), str(exact[0]["identity_decision_id"])


def _reviewed_resource_disposition(
    settings: Settings, resolution_case_id: str
) -> tuple[str, str] | None:
    with evidence_connection(settings) as connection:
        rows = connection.execute(
            """
            SELECT event.resource_id,acquisition.acquisition_case_id
            FROM evidence_acquisition_case AS acquisition
            JOIN evidence_acquisition_state AS state USING(acquisition_case_id)
            JOIN evidence_acquisition_event AS event USING(acquisition_case_id)
            JOIN evidence_resource_offer AS offer USING(resource_offer_id)
            JOIN evidence_provider_observation AS observation USING(provider_observation_id)
            JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
            JOIN evidence_provider_request AS request USING(provider_request_id)
            WHERE request.resolution_case_id=? AND state.state='acquired'
              AND event.event_kind='fetch_succeeded' AND event.resource_id IS NOT NULL
            ORDER BY event.occurred_at DESC,event.acquisition_event_id DESC
            """,
            (resolution_case_id,),
        ).fetchall()
        blocked = connection.execute(
            """
            SELECT assessment.decision,assessment.rights_status,state.state
            FROM evidence_acquisition_case AS acquisition
            JOIN evidence_acquisition_state AS state USING(acquisition_case_id)
            JOIN evidence_rights_assessment AS assessment USING(rights_assessment_id)
            JOIN evidence_resource_offer AS offer USING(resource_offer_id)
            JOIN evidence_provider_observation AS observation USING(provider_observation_id)
            JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
            JOIN evidence_provider_request AS request USING(provider_request_id)
            WHERE request.resolution_case_id=? AND state.state='blocked'
            ORDER BY acquisition.created_at DESC
            """,
            (resolution_case_id,),
        ).fetchall()
    if len(rows) == 1:
        return str(rows[0]["resource_id"]), str(rows[0]["acquisition_case_id"])
    if not rows and blocked and all(
        row["decision"] in {"metadata_only", "blocked"} for row in blocked
    ):
        return None
    if len(rows) != 1:
        raise CanonicalizationEligibilityError(
            f"{resolution_case_id}: expected one acquired or explicitly blocked reviewed resource disposition, found acquired={len(rows)} blocked={len(blocked)}"
        )
    raise AssertionError("unreachable resource disposition")


def _institution_from_authors(
    authors: Iterable[dict[str, object]], *, provenance_urn: str
) -> ReviewedInstitutionResolution:
    institutions: list[str] = []
    for author in authors:
        for value in author.get("affiliations", []) or []:
            text = str(value).strip()
            if text and text not in institutions:
                institutions.append(text)
    if institutions:
        return ReviewedInstitutionResolution(
            status="verified",
            institutions=tuple(institutions),
            reason_code="official_author_affiliations_present",
            reason_text="机构来自已审核官方作者 affiliation 字段；未从作者姓名或本地上下文推断。",
            checked_source_fields=("official_authors.affiliations",),
        )
    return ReviewedInstitutionResolution(
        status="unresolved",
        institutions=(),
        reason_code="official_affiliation_field_empty",
        reason_text="已检查官方作者 affiliation 字段但未得到机构；保持未解析，不按作者姓名猜测。",
        checked_source_fields=("official_authors.affiliations", provenance_urn),
    )


def build_crossref_reviewed_manifest(
    settings: Settings,
    decision_paths: tuple[Path, ...],
    *,
    review_id: str,
    reviewed_by: str,
    reviewed_at: str,
    idempotency_key: str,
    provenance_urn: str,
    reconciliation_overrides: Mapping[str, Mapping[str, str]] | None = None,
    identity_verdicts: Mapping[str, Mapping[str, object]] | None = None,
    include_source_candidates: frozenset[str] | None = None,
) -> ReviewedCanonicalizationManifest:
    """Translate reviewed Crossref JSONL tiers without weakening fact boundaries."""

    rows: dict[str, dict[str, object]] = {}
    for path in decision_paths:
        for row in _jsonl(path):
            source_id = str(row.get("candidate_id") or "")
            if not source_id:
                raise ValueError(f"{path}: accepted decision lacks candidate_id")
            prior = rows.get(source_id)
            if prior is not None and prior != row:
                raise ValueError(f"Crossref accepted tiers conflict for {source_id}")
            rows[source_id] = row
    items: list[ReviewedCanonicalizationItem] = []
    tier_map = {
        "four_field_strict": "strict_four_field",
        "four_field_strict_from_raw_archive": "strict_four_field",
        "abbreviated_author": "accepted_abbreviated_author",
        "local_venue_unstated": "accepted_local_venue_unstated",
        "explicit_local_identifier_ssrn": "accepted_explicit_local_identifier",
    }
    for source_id, row in sorted(rows.items()):
        if include_source_candidates is not None and source_id not in include_source_candidates:
            continue
        if not _crossref_reconciliation_allows(source_id, reconciliation_overrides):
            continue
        verifier = (identity_verdicts or {}).get(source_id)
        if verifier is not None and str(verifier.get("identity_verdict") or "") != "PASS":
            continue
        doi = normalize_identifier("doi", str(row["selected_doi"]))
        matches = [
            match
            for match in row.get("strict_matches", [])
            if normalize_identifier("doi", str(match["doi"])) == doi
        ]
        if len(matches) != 1:
            raise ValueError(f"{source_id}: accepted DOI has no unique reviewed metadata match")
        match = matches[0]
        exact_message = _crossref_exact_message(row)
        official_abstract_excerpt = reviewed_crossref_official_abstract_excerpt(row)
        if (
            official_abstract_excerpt is not None
            and str(official_abstract_excerpt.locator.get("title") or "")
            != str(match["title"])
        ):
            raise ValueError(
                f"{source_id}: Crossref deposit abstract title differs from reviewed identity"
            )
        if verifier is not None:
            verifier_doi = normalize_identifier("doi", str(verifier.get("selected_doi") or ""))
            if verifier_doi != doi:
                raise ValueError(
                    f"{source_id}: independent verifier DOI differs from reviewed decision"
                )
        resolution_case_id, identity_decision_id = _identity_for_source(
            settings,
            source_candidate_id=source_id,
            scheme="doi",
            normalized_identifier=doi,
        )
        official_authors = list(match.get("authors", []))
        tier_key = str(row.get("identity_match_tier") or "")
        local_claim = dict(row.get("local_claim") or {})
        verifier_tier: Mapping[str, object] = {}
        verifier_local_claim: Mapping[str, object] = {}
        if verifier is not None:
            raw_tier = verifier.get("tier_review")
            raw_local = verifier.get("local_claim")
            if not isinstance(raw_tier, Mapping) or not isinstance(raw_local, Mapping):
                raise ValueError(f"{source_id}: malformed independent verifier overlay")
            verifier_tier = raw_tier
            verifier_local_claim = raw_local
            if str(verifier_tier.get("as_produced") or "") != tier_key:
                raise ValueError(
                    f"{source_id}: independent verifier is not bound to the produced tier"
                )
            tier_key = str(verifier_tier.get("required") or "")
        local_venue = str(
            verifier_local_claim.get("venue_from_archive")
            if verifier_local_claim
            else local_claim.get("venue_or_publisher")
            or ""
        ).strip()
        venues = [str(value) for value in match.get("venues", []) if str(value).strip()]
        endpoint = str((row.get("direct_doi_verification") or {}).get("endpoint") or f"https://doi.org/{doi}")
        response_hash = str(
            (row.get("direct_doi_verification") or {}).get("response_sha256") or ""
        )
        metadata_provenance = (
            f"qrh:evidence:crossref-exact-doi:{doi}:sha256:{response_hash}"
            if len(response_hash) == 64
            else f"qrh:evidence:crossref-reviewed-doi:{doi}"
        )
        crossref_subjects = [
            str(value).strip()
            for value in exact_message.get("subject", []) or []
            if str(value).strip()
        ]
        crossref_type = str(
            exact_message.get("type") or match.get("type") or "scholarly-work"
        ).strip()
        source_category_values = (
            crossref_subjects
            if crossref_subjects
            else [f"type:{crossref_type}"]
        )
        mapped_categories = _broad_categories(
            source_system="crossref",
            source_codes=source_category_values,
            title=str(match["title"]),
            venue=venues[0] if venues else "",
        )
        source_categories = tuple(
            ReviewedSourceCategory(
                code=value,
                display_name=value,
                is_primary=index == 0,
                fact_origin="official_external",
            )
            for index, value in enumerate(source_category_values)
        )
        authors = tuple(
            ReviewedAuthor(
                name=" ".join(
                    part
                    for part in (str(author.get("given") or "").strip(), str(author.get("family") or "").strip())
                    if part
                ),
                affiliations=tuple(str(value) for value in author.get("affiliations", []) or []),
                name_form="full",
                fact_origin="official_external",
            )
            for author in official_authors
        )
        year_values = [str(value) for value in match.get("year_values", []) if str(value)]
        metadata = ReviewedMetadata(
            title=str(match["title"]),
            publication_date=year_values[0] if year_values else None,
            authors=authors,
            author_resolution=(
                "verified_abbreviated_local"
                if tier_key == "abbreviated_author"
                else "verified_full_external"
            ),
            venue=(
                ReviewedVenueClaim(
                    value=venues[0],
                    volume=(str(exact_message.get("volume") or "").strip() or None),
                    issue=(str(exact_message.get("issue") or "").strip() or None),
                    pages=(str(exact_message.get("page") or "").strip() or None),
                    fact_origin="official_external",
                    local_venue_stated=bool(local_venue),
                    provenance_urn=metadata_provenance,
                )
                if venues
                else None
            ),
            categories=mapped_categories,
            category_fact_origin="deterministic_mapping",
            category_assertion=ReviewedCategoryAssertion(
                source_system="crossref",
                source_categories=source_categories,
                primary_source_category=source_categories[0].code,
                mapping_policy_version=BROAD_CATEGORY_MAPPING_POLICY,
                primary_mapped_category=mapped_categories[0],
                assertion_status="verified_external",
                provenance_urn=metadata_provenance,
            ),
            institutions=_institution_from_authors(
                official_authors, provenance_urn=metadata_provenance
            ),
            external_links=(
                ReviewedExternalLink(kind="doi", url=f"https://doi.org/{doi}"),
                ReviewedExternalLink(kind="landing", url=f"https://doi.org/{doi}"),
            ),
            source_kind="registry",
            review_tier=tier_map.get(tier_key, "human_reconciled"),
            assertion_boundaries={
                **dict(row.get("assertion_boundaries") or {}),
                **(
                    {
                        "independent_identity_verifier": {
                            "identity_verdict": verifier.get("identity_verdict"),
                            "consumption_verdict_as_produced": verifier.get(
                                "consumption_verdict_as_produced"
                            ),
                            "produced_tier": verifier_tier.get("as_produced"),
                            "applied_tier": verifier_tier.get("required"),
                            "tier_reconciliation": (
                                "overlay_applied_without_mutating_frozen_upstream"
                            ),
                            "local_venue_from_archive": local_venue or None,
                            "notes": verifier.get("notes") or [],
                        },
                        "official_bibliographic_display": {
                            "venue": venues[0] if venues else None,
                            "volume": exact_message.get("volume"),
                            "issue": exact_message.get("issue"),
                            "pages": exact_message.get("page"),
                            "precedence": "official_exact_doi_metadata",
                        },
                    }
                    if verifier is not None
                    else {}
                ),
            },
            provenance_urn=metadata_provenance,
        )
        items.append(
            ReviewedCanonicalizationItem(
                item_key=f"crossref:{source_id}:{doi}",
                treatment="formal_citation",
                source_candidate_id=source_id,
                paper_source_candidate_id=source_id,
                resolution_case_id=resolution_case_id,
                identity_decision_id=identity_decision_id,
                metadata=metadata,
                official_abstract_excerpt=official_abstract_excerpt,
                resource=None,
                core_conclusions=(
                    (
                        ReviewedConclusion(
                            text=official_abstract_excerpt.text,
                            evidence_scope="official_abstract",
                            provenance_urn=(
                                official_abstract_excerpt.provenance_urn
                                + ":source-claim"
                            ),
                        ),
                    )
                    if official_abstract_excerpt is not None
                    else ()
                ),
            )
        )
    return ReviewedCanonicalizationManifest(
        schema_version="qrh-reviewed-evidence-expansion/v1",
        review_id=review_id,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
        idempotency_key=idempotency_key,
        provenance_urn=provenance_urn,
        items=tuple(items),
    )


def method_origin_inputs_from_arxiv_readings(
    reading_records_path: Path | Sequence[Path],
    *,
    provenance_urn: str,
    include_source_candidates: frozenset[str] | None = None,
) -> tuple[MethodOriginCandidateInput, ...]:
    output: list[MethodOriginCandidateInput] = []
    rows: list[dict[str, object]] = []
    for path in _path_tuple(reading_records_path):
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows.extend(payload["items"])
    for row in rows:
        if (
            include_source_candidates is not None
            and str(row["source_candidate_id"]) not in include_source_candidates
        ):
            continue
        relation = row["archive_relation"]
        if relation["treatment"] != "associated_method_origin":
            continue
        output.append(
            MethodOriginCandidateInput(
                original_source_candidate_id=row["source_candidate_id"],
                derived_source_candidate_id=relation["paper_source_candidate_id"],
                identifier_scheme="arxiv",
                identifier_value=row["arxiv_id"],
                paper_title_claim=row["official_title"],
                publication_year=int(str(row["arxiv_id"])[:2]) + 2000,
                rationale=relation["local_basis"],
                provenance_urn=(
                    f"{provenance_urn}:{row['source_candidate_id']}:{row['arxiv_id']}"
                ),
            )
        )
    return tuple(output)


def build_arxiv_reviewed_manifest(
    settings: Settings,
    materials_manifest_path: Path | Sequence[Path],
    reading_records_path: Path | Sequence[Path],
    *,
    review_id: str,
    reviewed_by: str,
    reviewed_at: str,
    idempotency_key: str,
    provenance_urn: str,
    include_source_candidates: frozenset[str] | None = None,
) -> ReviewedCanonicalizationManifest:
    material_by_source: dict[str, tuple[Path, dict[str, object]]] = {}
    reading_rows: list[tuple[dict[str, object], dict[str, object]]] = []
    for path in _path_tuple(materials_manifest_path):
        materials = json.loads(path.read_text(encoding="utf-8"))
        for row in materials["items"]:
            source_id = str(row["source_candidate_id"])
            if source_id in material_by_source:
                raise ValueError(f"duplicate arXiv material source candidate: {source_id}")
            material_by_source[source_id] = (path.parent.resolve(strict=True), row)
    for path in _path_tuple(reading_records_path):
        readings = json.loads(path.read_text(encoding="utf-8"))
        fact_boundary = _reading_fact_boundary(readings.get("fact_boundary"), path=path)
        for row in readings["items"]:
            reading_rows.append((row, fact_boundary))
    items: list[ReviewedCanonicalizationItem] = []
    for reading, reading_fact_boundary in reading_rows:
        source_id = str(reading["source_candidate_id"])
        if include_source_candidates is not None and source_id not in include_source_candidates:
            continue
        materials_root, material = material_by_source[source_id]
        official = material["official_metadata"]
        relation = reading["archive_relation"]
        paper_source_id = str(relation["paper_source_candidate_id"])
        arxiv_id = normalize_identifier("arxiv", str(reading["arxiv_id"]))
        resolution_case_id, identity_decision_id = _identity_for_source(
            settings,
            source_candidate_id=paper_source_id,
            scheme="arxiv",
            normalized_identifier=arxiv_id,
        )
        resource_disposition = _reviewed_resource_disposition(
            settings, resolution_case_id
        )
        page_hashes = {
            int(value["page"]): str(value["text_sha256"])
            for value in material["pdf_validation"]["page_text"]
        }
        findings = [
            finding
            for finding in reading.get("main_findings", [])
            if finding.get("status") == "source_finding"
        ] if resource_disposition is not None else []
        reading_conclusions: list[ReviewedReadingConclusion] = []
        conclusions: list[ReviewedConclusion] = []
        for finding in findings:
            evidence = finding["evidence"][0]
            page = int(evidence["pdf_pages"][0])
            text = str(finding["text_zh"])
            locator_hashes = evidence.get("page_text_sha256_by_page")
            locator_alias = evidence.get("page_text_sha256")
            if locator_hashes is not None:
                normalized_hashes = {
                    str(key): str(value)
                    for key, value in dict(locator_hashes).items()
                }
                normalized_alias = {
                    str(key): str(value) for key, value in dict(locator_alias or {}).items()
                }
                if (
                    normalized_hashes != normalized_alias
                    or normalized_hashes.get(str(page)) != page_hashes[page]
                ):
                    raise ValueError(
                        f"{source_id}: reviewed reading locator hash differs from material"
                    )
            locator = ReviewedFulltextLocator(
                page_number=page,
                page_text_sha256=page_hashes[page],
                support_text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                locator={
                    "pdf_pages": evidence["pdf_pages"],
                    "section": evidence["section"],
                    "claim_status": finding["status"],
                    "page_text_sha256_by_page": evidence.get(
                        "page_text_sha256_by_page",
                        {str(value): page_hashes[int(value)] for value in evidence["pdf_pages"]},
                    ),
                    "source_pdf_sha256": evidence.get("source_pdf_sha256"),
                    "extracted_text_sha256": evidence.get("extracted_text_sha256"),
                    "locator_version": evidence.get(
                        "locator_version", "reviewed-material-page-hash/v1"
                    ),
                },
            )
            reading_conclusions.append(
                ReviewedReadingConclusion(text=text, source_locator=locator)
            )
            conclusions.append(
                ReviewedConclusion(
                    text=text,
                    evidence_scope="fulltext_reading",
                    source_locator=locator,
                    provenance_urn=(
                        f"qrh:evidence:reviewed-fulltext:{arxiv_id}:page:{page}:"
                        f"sha256:{page_hashes[page]}"
                    ),
                )
            )
        official_abstract_excerpt = reviewed_arxiv_official_abstract_excerpt(
            materials_root, material
        )
        if not conclusions:
            conclusions.append(
                ReviewedConclusion(
                    text=official_abstract_excerpt.text,
                    evidence_scope="official_abstract",
                    provenance_urn=(
                        official_abstract_excerpt.provenance_urn + ":source-claim"
                    ),
                )
            )
        metadata_provenance = official_abstract_excerpt.provenance_urn
        authors = tuple(
            ReviewedAuthor(
                name=str(name),
                affiliations=(),
                name_form="full",
                fact_origin="official_external",
            )
            for name in official["authors"]
        )
        official_categories = tuple(str(value) for value in official["categories"])
        primary_official_category = str(
            official.get("primary_category") or official_categories[0]
        )
        ordered_official_categories = (
            primary_official_category,
            *(value for value in official_categories if value != primary_official_category),
        )
        mapped_categories = _broad_categories(
            source_system="arxiv",
            source_codes=ordered_official_categories,
            title=str(official["title"]),
            venue=str(official.get("journal_reference") or ""),
        )
        source_categories = tuple(
            ReviewedSourceCategory(
                code=value,
                display_name=value,
                is_primary=index == 0,
                fact_origin="official_external",
            )
            for index, value in enumerate(ordered_official_categories)
        )
        metadata = ReviewedMetadata(
            title=official["title"],
            publication_date=official["published"],
            authors=authors,
            author_resolution="verified_full_external",
            venue=(
                ReviewedVenueClaim(
                    value=official["journal_reference"],
                    fact_origin="official_external",
                    local_venue_stated=False,
                    provenance_urn=metadata_provenance,
                )
                if official.get("journal_reference")
                else None
            ),
            categories=mapped_categories,
            category_fact_origin="deterministic_mapping",
            category_assertion=ReviewedCategoryAssertion(
                source_system="arxiv",
                source_categories=source_categories,
                primary_source_category=primary_official_category,
                mapping_policy_version=BROAD_CATEGORY_MAPPING_POLICY,
                primary_mapped_category=mapped_categories[0],
                assertion_status="verified_external",
                provenance_urn=metadata_provenance,
            ),
            institutions=ReviewedInstitutionResolution(
                status="unresolved",
                institutions=(),
                reason_code="arxiv_author_affiliations_not_provided",
                reason_text="已审核 arXiv Atom/摘要页作者字段，但该来源未提供可核验机构；保持未解析。",
                checked_source_fields=("atom.authors", "abstract_page.authors"),
            ),
            external_links=(
                ReviewedExternalLink(kind="landing", url=official["official_urls"]["abstract"]),
                ReviewedExternalLink(kind="repository", url=official["official_urls"]["pdf"]),
            ),
            source_kind="repository",
            review_tier="official_repository_full_material",
            assertion_boundaries={
                "official_metadata": "source_fact",
                "fulltext_findings": "reviewed_source_finding_with_page_hash",
                "analysis_inference": "excluded_from_core_conclusions",
                "formal_citation_claim_allowed": material["formal_citation_claim_allowed"],
            },
            provenance_urn=metadata_provenance,
        )
        resource = None
        if resource_disposition is not None:
            resource_id, acquisition_case_id = resource_disposition
            resource = ReviewedResource(
                resource_id=resource_id,
                acquisition_case_id=acquisition_case_id,
                reading_result=ReviewedReadingResult(
                    worker_kind="human",
                    analysis=json.dumps(reading, ensure_ascii=False, sort_keys=True),
                    core_conclusions=tuple(reading_conclusions),
                    fact_boundary=reading_fact_boundary,
                    provenance_urn=f"qrh:evidence:reviewed-reading:{arxiv_id}",
                ),
            )
        items.append(
            ReviewedCanonicalizationItem(
                item_key=f"arxiv:{source_id}:{arxiv_id}",
                treatment=relation["treatment"],
                source_candidate_id=source_id,
                paper_source_candidate_id=paper_source_id,
                resolution_case_id=resolution_case_id,
                identity_decision_id=identity_decision_id,
                metadata=metadata,
                official_abstract_excerpt=official_abstract_excerpt,
                resource=resource,
                core_conclusions=tuple(conclusions),
                association_rationale=(
                    relation["local_basis"]
                    if relation["treatment"] == "associated_method_origin"
                    else None
                ),
            )
        )
    return ReviewedCanonicalizationManifest(
        schema_version="qrh-reviewed-evidence-expansion/v1",
        review_id=review_id,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
        idempotency_key=idempotency_key,
        provenance_urn=provenance_urn,
        items=tuple(items),
    )
