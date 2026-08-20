from __future__ import annotations

from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
from typing import Any, Iterable
from urllib.parse import urlsplit

from quant_hub.config import (
    ConfigurationError,
    Settings,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)
from quant_hub.platform.db import immediate_transaction
from quant_hub.platform.workflow import canonical_json

from .database import evidence_connection, initialize_evidence_database
from .export import InventoryExport, export_candidate_inventory, export_inventory
from .ids import citation_id_for_locator, citation_id_for_marker, stable_evidence_id
from .repository import EvidenceConflict, EvidenceRepository
from .resources import EvidenceResourceStore, StagedPdf


PACKAGE_SCHEMA_VERSION = "qrh.evidence-bulk-preprocess/v1"
NORMALIZED_RESOURCE_SCHEMA_VERSION = "qrh.normalized-evidence-resource/v1"
IMPORT_SCHEMA_VERSION = "qrh.archive-evidence-import/v1"
EXPECTED_CANDIDATES = 245
EXPECTED_LEDGER_ENTRIES = 5_181
EXPECTED_LINKED_ENTRIES = 5_146
EXPECTED_UNLINKED_ENTRIES = 35
EXPECTED_CROSSREF_SEARCHES = 158
EXPECTED_EXTERNAL_CANDIDATES = 474
EXPECTED_EXTERNAL_ASSERTIONS = 8
EXPECTED_NETWORK_ATTEMPTS = 204
EXPECTED_RESOURCES = 18
EXPECTED_CANONICAL_MARKERS = 4_630
EXPECTED_PAPER_CATEGORIES = 4
EXPECTED_CATEGORY_ASSIGNMENTS = 23
EXPECTED_CORE_CONCLUSIONS = 18
EXPECTED_INSTITUTION_RESOLUTIONS = 18
EXPECTED_READING_RUNS = 19
EXPECTED_SUCCESSFUL_READING_RUNS = 18

CATEGORY_MAPPING_POLICY = "arxiv-subject-to-qrh-paper-category/v1"
FULLTEXT_READING_ALGORITHM = "pymupdf-text-pages-and-source-bounded-claims/v1"
_CATEGORY_DISPLAY_NAMES = {
    "quantitative_finance": "量化金融",
    "mathematics": "数学与统计",
    "machine_learning": "机器学习",
    "other": "其他",
}
_AFFILIATION_META_FIELDS = (
    "citation_author_affiliation",
    "citation_author_institution",
    "citation_institution",
)

_RESOURCE_NAME_RE = re.compile(
    r"^(?P<candidate>P[0-9]{3})_arxiv_(?P<arxiv>[0-9]{4}\.[0-9]{4,5})\.pdf$"
)
_CANDIDATE_IN_REQUEST_RE = re.compile(r"(?:^|:)(P[0-9]{3})(?:$|:)")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceBulkError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedBulkPackage:
    root: Path
    input_manifest_hash: str
    artifact_manifest_hash: str
    declared_artifact_manifest_hash: str
    normalized_resource_manifest_hash: str
    fulltext_reading_results_hash: str
    source_file_hashes: dict[str, str]
    captured_at: str
    candidates: tuple[dict[str, Any], ...]
    occurrences: tuple[dict[str, Any], ...]
    crossref_searches: tuple[dict[str, Any], ...]
    external_assertions: tuple[dict[str, Any], ...]
    network_attempts: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]
    reading_results: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class BulkImportResult:
    import_receipt_id: str
    created: bool
    counts: dict[str, int]
    inventory: InventoryExport
    candidate_inventory: InventoryExport
    source_snapshot_hash: str
    normalized_resource_manifest_hash: str


@dataclass(frozen=True, slots=True)
class _CitationRow:
    citation_id: str
    canonical: tuple[object, ...]
    ledger: tuple[object, ...]
    binding: tuple[object, ...]
    relation: tuple[object, ...] | None


@dataclass(frozen=True, slots=True)
class OfficialPaperMaterial:
    source_candidate_id: str
    arxiv_id: str
    title: str
    authors: tuple[str, ...]
    publication_date: str
    abstract: str
    abstract_page_url: str
    abstract_page_sha256: str
    abstract_cache_path: str
    identity_source: str
    subjects: tuple["ArxivSubject", ...]


@dataclass(frozen=True, slots=True)
class ArxivSubject:
    code: str
    display_name: str
    is_primary: bool


class _ArxivMetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, list[str]] = {}
        self._inside_subjects = False
        self.subject_text: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        normalized_tag = tag.casefold()
        attributes = {key.casefold(): value for key, value in attrs}
        if normalized_tag == "td" and "subjects" in str(
            attributes.get("class") or ""
        ).split():
            self._inside_subjects = True
        if normalized_tag != "meta":
            return
        name = attributes.get("name")
        content = attributes.get("content")
        if name and content is not None:
            self.values.setdefault(name, []).append(content)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "td" and self._inside_subjects:
            self._inside_subjects = False

    def handle_data(self, data: str) -> None:
        if self._inside_subjects:
            self.subject_text.append(data)


def _arxiv_subjects(parser: _ArxivMetaParser, *, candidate_id: str) -> tuple[ArxivSubject, ...]:
    subject_text = " ".join(" ".join(parser.subject_text).split())
    matches = re.findall(
        r"(?:^|;\s*)([^;]+?)\s+\(([A-Za-z-]+\.[A-Za-z]{2})\)",
        subject_text,
    )
    subjects: list[ArxivSubject] = []
    seen: set[str] = set()
    for index, (display_name, code) in enumerate(matches):
        normalized_code = code.strip()
        if normalized_code.casefold() in seen:
            raise EvidenceBulkError(f"official abs page repeats a subject: {candidate_id}")
        seen.add(normalized_code.casefold())
        subjects.append(
            ArxivSubject(
                code=normalized_code,
                display_name=display_name.strip(),
                is_primary=index == 0,
            )
        )
    if not subjects or sum(subject.is_primary for subject in subjects) != 1:
        raise EvidenceBulkError(f"official abs page subjects are incomplete: {candidate_id}")
    return tuple(subjects)


def _classify_arxiv_subject(code: str) -> str:
    normalized = code.casefold()
    if normalized.startswith("q-fin."):
        return "quantitative_finance"
    if normalized.startswith("math.") or (
        normalized.startswith("stat.") and normalized != "stat.ml"
    ):
        return "mathematics"
    if normalized.startswith("cs.") or normalized == "stat.ml":
        return "machine_learning"
    return "other"


def _classified_categories(material: OfficialPaperMaterial) -> tuple[tuple[str, str, bool], ...]:
    classifications: dict[str, bool] = {}
    order: list[str] = []
    for subject in material.subjects:
        category_key = _classify_arxiv_subject(subject.code)
        if category_key not in classifications:
            classifications[category_key] = False
            order.append(category_key)
        classifications[category_key] = classifications[category_key] or subject.is_primary
    result = tuple(
        (key, _CATEGORY_DISPLAY_NAMES[key], classifications[key]) for key in order
    )
    if sum(is_primary for _, _, is_primary in result) != 1:
        raise EvidenceBulkError(
            f"arXiv subject mapping does not yield one primary category: {material.source_candidate_id}"
        )
    return result


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path) -> bytes:
    try:
        ensure_no_reparse_components(path)
        info = path.lstat()
    except (ConfigurationError, FileNotFoundError, OSError) as error:
        raise EvidenceBulkError(f"required evidence input is unavailable: {path}") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat_is_reparse_point(info)
        or info.st_nlink != 1
    ):
        raise EvidenceBulkError(f"evidence input is not a regular single-link file: {path}")
    before = (info.st_size, info.st_mtime_ns)
    payload = path.read_bytes()
    after = path.lstat()
    if before != (after.st_size, after.st_mtime_ns) or not stat.S_ISREG(after.st_mode):
        raise EvidenceBulkError(f"evidence input changed while being read: {path}")
    return payload


def _json_bytes(payload: bytes, *, label: str) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceBulkError(f"invalid UTF-8 JSON in {label}") from error


def _jsonl_bytes(payload: bytes, *, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = payload.decode("utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError("JSONL row must be an object")
            rows.append(value)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise EvidenceBulkError(f"invalid JSONL row in {label}:{line_number}") from error
    return rows


def _safe_relative(value: str) -> PurePosixPath:
    if not value or "\\" in value or ":" in value:
        raise EvidenceBulkError(f"non-canonical relative path: {value!r}")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in result.parts):
        raise EvidenceBulkError(f"relative path escapes its managed root: {value!r}")
    return result


def _contained_path(root: Path, relative: str) -> Path:
    parts = _safe_relative(relative).parts
    candidate = root.joinpath(*parts).absolute()
    try:
        candidate.relative_to(root.absolute())
    except ValueError as error:
        raise EvidenceBulkError(f"input path escapes package root: {relative}") from error
    return candidate


def _artifact_entries(root: Path) -> tuple[dict[str, str], str]:
    manifest_path = root / "artifact_manifest.sha256"
    payload = _read_regular(manifest_path)
    declared: dict[str, str] = {}
    for line_number, raw_line in enumerate(payload.decode("utf-8").splitlines(), start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", raw_line)
        if match is None:
            raise EvidenceBulkError(f"invalid artifact manifest line {line_number}")
        digest, relative = match.groups()
        _safe_relative(relative)
        if relative in declared:
            raise EvidenceBulkError(f"duplicate artifact manifest path: {relative}")
        artifact = _contained_path(root, relative)
        actual = _sha256(_read_regular(artifact))
        must_match = (
            relative.startswith("resources/")
            or relative in {"input_manifest.json", "verification_report.json"}
        )
        if must_match and actual != digest:
            raise EvidenceBulkError(f"critical artifact hash mismatch: {relative}")
        declared[relative] = digest
    return declared, _sha256(payload)


def _resource_manifest_rows(root: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    payload = _read_regular(root / "resource_manifest.jsonl")
    rows = _jsonl_bytes(payload, label="resource_manifest.jsonl")
    raw_hashes: dict[str, str] = {}
    for raw_line in payload.splitlines():
        if not raw_line:
            continue
        row = json.loads(raw_line.decode("utf-8"))
        candidate = str(row.get("candidate_id", ""))
        if not candidate or candidate in raw_hashes:
            raise EvidenceBulkError("primary resource manifest candidate IDs must be unique")
        raw_hashes[candidate] = _sha256(raw_line)
    return rows, raw_hashes


def _official_paper_material(
    root: Path,
    candidate: dict[str, Any],
    *,
    candidate_id: str,
    arxiv_id: str,
) -> OfficialPaperMaterial:
    verification = candidate.get("arxiv_verification") or {}
    abstract_page = verification.get("abstract_page") or {}
    request = abstract_page.get("request") or {}
    body_relative = f"cache/arxiv/abs_{candidate_id}_{arxiv_id}.body"
    body = _read_regular(_contained_path(root, body_relative))
    if (
        request.get("status") != "success"
        or request.get("http_status") != 200
        or request.get("mime_type") != "text/html"
        or request.get("sha256") != _sha256(body)
    ):
        raise EvidenceBulkError(f"official abs-page audit is incomplete: {candidate_id}")
    request_url = str(request.get("final_url") or request.get("request_url") or "")
    parsed_url = urlsplit(request_url)
    if (parsed_url.scheme, (parsed_url.hostname or "").lower()) != (
        "https",
        "arxiv.org",
    ) or not parsed_url.path.startswith("/abs/"):
        raise EvidenceBulkError(f"identity source is not an official arXiv abs page: {candidate_id}")
    try:
        html = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceBulkError(f"official abs page is not UTF-8: {candidate_id}") from error
    parser = _ArxivMetaParser()
    parser.feed(html)
    values = parser.values
    subjects = _arxiv_subjects(parser, candidate_id=candidate_id)
    unexpected_affiliations = {
        field_name: values[field_name]
        for field_name in _AFFILIATION_META_FIELDS
        if values.get(field_name)
    }
    if unexpected_affiliations:
        raise EvidenceBulkError(
            f"official abs page now exposes affiliation metadata and requires reviewed mapping: {candidate_id}"
        )
    required_single = {
        "citation_arxiv_id": arxiv_id,
    }
    for name, expected in required_single.items():
        if values.get(name) != [expected]:
            raise EvidenceBulkError(
                f"official abs page strong identifier differs for {candidate_id}: {name}"
            )
    titles = values.get("citation_title") or []
    dates = values.get("citation_date") or []
    abstracts = values.get("citation_abstract") or []
    authors = values.get("citation_author") or []
    if len(titles) != 1 or len(dates) != 1 or len(abstracts) != 1 or not authors:
        raise EvidenceBulkError(f"official abs metadata is incomplete: {candidate_id}")

    extracted = (abstract_page.get("extracted_metadata") or {}).get("meta") or {}
    for name in (
        "citation_arxiv_id",
        "citation_title",
        "citation_date",
        "citation_author",
    ):
        if extracted.get(name) != values.get(name):
            raise EvidenceBulkError(
                f"cached HTML and E extracted metadata differ for {candidate_id}: {name}"
            )
    api = verification.get("official_metadata")
    identity_source = (
        "official_arxiv_api_and_abstract_page"
        if isinstance(api, dict) and api.get("arxiv_id") == arxiv_id
        else "official_arxiv_abstract_page_metadata_fallback"
    )
    return OfficialPaperMaterial(
        source_candidate_id=candidate_id,
        arxiv_id=arxiv_id,
        title=str(titles[0]),
        authors=tuple(str(value) for value in authors),
        publication_date=str(dates[0]).replace("/", "-"),
        abstract=str(abstracts[0]),
        abstract_page_url=request_url,
        abstract_page_sha256=_sha256(body),
        abstract_cache_path=body_relative,
        identity_source=identity_source,
        subjects=subjects,
    )


def derive_normalized_resource_manifest(
    package_root: Path,
    *,
    artifact_entries: dict[str, str] | None = None,
    artifact_manifest_hash: str | None = None,
    candidates: Iterable[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], ...]:
    """从三方审计事实重建 18 行资源 manifest；不会据文件名升级论文身份。"""

    root = package_root.absolute()
    if artifact_entries is None or artifact_manifest_hash is None:
        artifact_entries, artifact_manifest_hash = _artifact_entries(root)
    if candidates is None:
        candidates = _jsonl_bytes(
            _read_regular(root / "candidate_ledger.jsonl"), label="candidate_ledger.jsonl"
        )
    candidate_by_id = {str(row["candidate_id"]): row for row in candidates}
    primary_rows, primary_raw_hashes = _resource_manifest_rows(root)
    primary_by_candidate = {str(row["candidate_id"]): row for row in primary_rows}
    primary_manifest_file_hash = _sha256(_read_regular(root / "resource_manifest.jsonl"))

    resource_paths = sorted(
        path
        for path in artifact_entries
        if path.startswith("resources/") and path.endswith(".pdf")
    )
    if len(resource_paths) != EXPECTED_RESOURCES:
        raise EvidenceBulkError(
            f"artifact manifest must bind exactly {EXPECTED_RESOURCES} PDF resources"
        )

    normalized: list[dict[str, Any]] = []
    for relative in resource_paths:
        name_match = _RESOURCE_NAME_RE.fullmatch(PurePosixPath(relative).name)
        if name_match is None:
            raise EvidenceBulkError(f"unexpected audited PDF name: {relative}")
        candidate_id = name_match.group("candidate")
        arxiv_id = name_match.group("arxiv")
        candidate = candidate_by_id.get(candidate_id)
        if candidate is None:
            raise EvidenceBulkError(f"resource has no candidate ledger row: {candidate_id}")

        cache_relative = f"cache/arxiv/pdf_{candidate_id}_{arxiv_id}.meta.json"
        cache_path = _contained_path(root, cache_relative)
        cache_payload = _read_regular(cache_path)
        cache = _json_bytes(cache_payload, label=cache_relative)
        if not isinstance(cache, dict):
            raise EvidenceBulkError(f"cache metadata must be an object: {cache_relative}")
        resource_path = _contained_path(root, relative)
        resource_payload = _read_regular(resource_path)
        declared_sha = artifact_entries[relative]
        if (
            not resource_payload.startswith(b"%PDF-")
            or _sha256(resource_payload) != declared_sha
            or cache.get("sha256") != declared_sha
            or cache.get("bytes") != len(resource_payload)
            or cache.get("status") != "success"
            or cache.get("http_status") != 200
            or cache.get("mime_type") != "application/pdf"
        ):
            raise EvidenceBulkError(f"cache/artifact/PDF three-way verification failed: {relative}")
        request_url = str(cache.get("request_url", ""))
        final_url = str(cache.get("final_url", ""))
        if any(
            (urlsplit(url).scheme, (urlsplit(url).hostname or "").lower())
            != ("https", "arxiv.org")
            for url in (request_url, final_url)
        ):
            raise EvidenceBulkError(f"resource is not from the official HTTPS arXiv endpoint: {relative}")

        verification = candidate.get("arxiv_verification") or {}
        abstract_page = verification.get("abstract_page") or {}
        abstract_request = abstract_page.get("request") or {}
        license_urls = abstract_page.get("license_urls") or []
        if (
            verification.get("requested_arxiv_id") != arxiv_id
            or abstract_request.get("status") != "success"
            or not license_urls
        ):
            raise EvidenceBulkError(f"candidate-bound rights evidence is incomplete: {candidate_id}")
        official_material = _official_paper_material(
            root,
            candidate,
            candidate_id=candidate_id,
            arxiv_id=arxiv_id,
        )

        primary = primary_by_candidate.get(candidate_id)
        primary_binding: dict[str, Any] | None = None
        if primary is not None:
            if (
                primary.get("sha256") != declared_sha
                or primary.get("bytes") != len(resource_payload)
                or primary.get("http_status") != 200
                or primary.get("mime_type") != "application/pdf"
            ):
                raise EvidenceBulkError(f"primary resource manifest conflicts: {candidate_id}")
            primary_binding = {
                "entry_sha256": primary_raw_hashes[candidate_id],
                "local_path": primary.get("local_path"),
                "request_url": primary.get("request_url"),
                "resource_id": primary.get("resource_id"),
                "resource_manifest_file_sha256": primary_manifest_file_hash,
            }

        lineage = (
            "primary_manifest_and_audited_artifact"
            if primary_binding is not None
            else "recovered_from_audited_artifact"
        )
        normalized.append(
            {
                "schema_version": NORMALIZED_RESOURCE_SCHEMA_VERSION,
                "resource_id": f"normalized-arxiv-{candidate_id}-{arxiv_id}",
                "candidate_id": candidate_id,
                "arxiv_id_claim": arxiv_id,
                "identity_effect": (
                    "resource_bytes_do_not_drive_identity; "
                    "official_abs_page_citation_arxiv_id_drives_canonical_identity"
                ),
                "lineage": lineage,
                "artifact": {
                    "artifact_manifest_file_sha256": artifact_manifest_hash,
                    "declared_sha256": declared_sha,
                    "local_path": relative,
                },
                "cache_metadata": {
                    "file_sha256": _sha256(cache_payload),
                    "local_path": cache_relative,
                },
                "official_abstract_page": {
                    "abstract_sha256": _sha256(official_material.abstract.encode("utf-8")),
                    "authors": list(official_material.authors),
                    "body_sha256": official_material.abstract_page_sha256,
                    "identity_source": official_material.identity_source,
                    "local_path": official_material.abstract_cache_path,
                    "publication_date": official_material.publication_date,
                    "title": official_material.title,
                    "url": official_material.abstract_page_url,
                },
                "request": {
                    "request_url": request_url,
                    "final_url": final_url,
                    "http_status": 200,
                    "media_type": "application/pdf",
                    "retrieved_at": cache.get("retrieved_at"),
                },
                "payload": {
                    "bytes": len(resource_payload),
                    "pdf_magic_valid": True,
                    "sha256": declared_sha,
                },
                "rights": {
                    "rights_status": "repository_distribution_only",
                    "redistribution_authorized_by_this_audit": False,
                    "paper_license_evidence_source": f"https://arxiv.org/abs/{arxiv_id}",
                    "paper_license_page_sha256": abstract_request.get("sha256"),
                    "paper_license_urls": license_urls,
                    "general_policy": "https://info.arxiv.org/help/license/index.html",
                    "interpretation": (
                        "official repository response is retained under its per-paper license; "
                        "this audit does not grant redistribution rights"
                    ),
                },
                "primary_resource_manifest_binding": primary_binding,
            }
        )
    normalized.sort(key=lambda row: str(row["candidate_id"]))
    recovered = sum(
        row["lineage"] == "recovered_from_audited_artifact" for row in normalized
    )
    if recovered != 17 or len(primary_rows) != 1:
        raise EvidenceBulkError("expected exactly 17 recovered rows and one primary-bound row")
    return tuple(normalized)


def normalized_resource_manifest_bytes(rows: Iterable[dict[str, Any]]) -> bytes:
    return (
        "\n".join(canonical_json(row) for row in rows) + "\n"
    ).encode("utf-8")


def verify_normalized_resource_manifest(
    package_root: Path,
    manifest_path: Path,
    *,
    artifact_entries: dict[str, str] | None = None,
    artifact_manifest_hash: str | None = None,
    candidates: Iterable[dict[str, Any]] | None = None,
) -> tuple[tuple[dict[str, Any], ...], str]:
    expected = derive_normalized_resource_manifest(
        package_root,
        artifact_entries=artifact_entries,
        artifact_manifest_hash=artifact_manifest_hash,
        candidates=candidates,
    )
    expected_bytes = normalized_resource_manifest_bytes(expected)
    actual = _read_regular(manifest_path)
    if actual != expected_bytes:
        raise EvidenceBulkError(
            "normalized resource manifest differs from independently reconstructed audit facts"
        )
    return expected, _sha256(actual)


def _default_normalized_manifest() -> Path:
    return Path(__file__).resolve().parents[3] / "fixtures" / "evidence" / "normalized_resource_manifest.jsonl"


def _verify_fulltext_reading_results(
    package_root: Path,
    manifest_path: Path,
    *,
    candidates: Iterable[dict[str, Any]],
    resources: Iterable[dict[str, Any]],
) -> tuple[tuple[dict[str, Any], ...], str]:
    try:
        import fitz  # type: ignore[import-not-found]
    except ImportError as error:
        raise EvidenceBulkError("fulltext replay requires the declared PyMuPDF dependency") from error

    payload = _read_regular(manifest_path)
    rows = _jsonl_bytes(payload, label="fulltext_reading_results.jsonl")
    candidate_by_id = {str(row["candidate_id"]): row for row in candidates}
    resource_by_id = {str(row["candidate_id"]): row for row in resources}
    if len(rows) != EXPECTED_RESOURCES or {
        str(row.get("source_candidate_id", "")) for row in rows
    } != set(resource_by_id):
        raise EvidenceBulkError("fulltext reading results must cover the exact 18-resource set")
    for row in rows:
        source_id = str(row["source_candidate_id"])
        resource = resource_by_id[source_id]
        candidate = candidate_by_id[source_id]
        material = _official_paper_material(
            package_root,
            candidate,
            candidate_id=source_id,
            arxiv_id=str(resource["arxiv_id_claim"]),
        )
        analysis_payload = row.get("analysis_payload")
        if not isinstance(analysis_payload, dict) or set(
            ("analysis", "core_conclusions", "fact_boundary")
        ) - set(analysis_payload):
            raise EvidenceBulkError(f"fulltext reading payload is incomplete: {source_id}")
        analysis = analysis_payload.get("analysis")
        conclusions = analysis_payload.get("core_conclusions")
        fact_boundary = analysis_payload.get("fact_boundary")
        if not isinstance(analysis, dict) or not isinstance(conclusions, list) or len(conclusions) != 1:
            raise EvidenceBulkError(f"fulltext reading analysis is malformed: {source_id}")
        fulltext = analysis.get("fulltext")
        identity_checks = analysis.get("document_identity_checks")
        if (
            not isinstance(fulltext, dict)
            or not isinstance(identity_checks, dict)
            or int(fulltext.get("page_count", 0)) <= 0
            or int(fulltext.get("page_count", 0))
            != int(fulltext.get("nonempty_page_count", -1))
            or len(fulltext.get("pages") or []) != int(fulltext.get("page_count", 0))
            or not _HASH_RE.fullmatch(str(fulltext.get("text_sha256", "")))
            or float(identity_checks.get("title_token_coverage_first_three_pages", 0)) < 0.8
            or float(identity_checks.get("official_abstract_token_coverage_fulltext", 0)) < 0.7
        ):
            raise EvidenceBulkError(f"fulltext extraction verification is incomplete: {source_id}")
        pdf_path = _contained_path(package_root, str(resource["artifact"]["local_path"]))
        pdf_payload = _read_regular(pdf_path)
        document = fitz.open(stream=pdf_payload, filetype="pdf")
        try:
            page_texts: list[str] = []
            page_records: list[dict[str, object]] = []
            detected_headings: list[dict[str, object]] = []
            heading_re = re.compile(
                r"^(?:[0-9]+(?:\.[0-9]+)*\s+)?"
                r"(?:conclusions?|concluding remarks|discussion(?: and conclusions?)?|summary)\s*$",
                re.IGNORECASE,
            )
            for page_number, page in enumerate(document, start=1):
                page_text = page.get_text("text", sort=True).replace(
                    "\r\n", "\n"
                ).replace("\r", "\n")
                page_texts.append(page_text)
                page_records.append(
                    {
                        "page": page_number,
                        "characters": len(page_text),
                        "text_sha256": _sha256(page_text.encode("utf-8")),
                    }
                )
                for line in page_text.splitlines():
                    normalized_line = " ".join(line.split())
                    if heading_re.fullmatch(normalized_line):
                        detected_headings.append(
                            {"page": page_number, "text": normalized_line}
                        )
        finally:
            document.close()
        full_text = "\f".join(page_texts)
        token_pattern = re.compile(r"[a-z0-9]{3,}")
        title_tokens = set(token_pattern.findall(material.title.casefold()))
        front_tokens = set(
            token_pattern.findall(" ".join(page_texts[:3]).casefold())
        )
        abstract_tokens = set(token_pattern.findall(material.abstract.casefold()))
        full_tokens = set(token_pattern.findall(full_text.casefold()))
        title_coverage = round(
            len(title_tokens & front_tokens) / max(1, len(title_tokens)), 6
        )
        abstract_coverage = round(
            len(abstract_tokens & full_tokens) / max(1, len(abstract_tokens)), 6
        )
        if (
            analysis.get("reading_mode")
            != "full_pdf_text_extraction_and_source_bounded_understanding"
            or analysis.get("algorithm_version") != FULLTEXT_READING_ALGORITHM
            or analysis.get("reader_engine") != "PyMuPDF"
            or analysis.get("reader_engine_version") != str(fitz.VersionBind)
            or fulltext.get("pages") != page_records
            or int(fulltext.get("characters", -1)) != len(full_text)
            or fulltext.get("text_sha256") != _sha256(full_text.encode("utf-8"))
            or any(not page_text.strip() for page_text in page_texts)
            or identity_checks.get("arxiv_id") != material.arxiv_id
            or identity_checks.get("official_title") != material.title
            or float(identity_checks.get("title_token_coverage_first_three_pages", -1))
            != title_coverage
            or float(identity_checks.get("official_abstract_token_coverage_fulltext", -1))
            != abstract_coverage
            or analysis.get("detected_conclusion_headings") != detected_headings
        ):
            raise EvidenceBulkError(
                f"fulltext replay differs from frozen per-page extraction: {source_id}"
            )
        conclusion = conclusions[0]
        source_provenance = (
            f"qrh:evidence:arxiv-abs:{material.arxiv_id}:sha256:{material.abstract_page_sha256}"
        )
        if (
            row.get("schema_version") != "qrh-evidence-fulltext-reading/v1"
            or row.get("result_status") != "succeeded"
            or row.get("arxiv_id") != material.arxiv_id
            or row.get("pdf_sha256") != resource["payload"]["sha256"]
            or row.get("pdf_bytes") != resource["payload"]["bytes"]
            or row.get("abstract_page_sha256") != material.abstract_page_sha256
            or conclusion.get("text") != material.abstract
            or conclusion.get("fact_status") != "source_claim"
            or conclusion.get("claim_scope") != "official_abstract_verbatim"
            or conclusion.get("verification_status")
            != "source_verified_not_human_fulltext_reviewed"
            or conclusion.get("provenance_urn") != source_provenance
            or not isinstance(fact_boundary, dict)
            or fact_boundary.get("fulltext_bytes") != "verified_pdf_source"
            or fact_boundary.get("fulltext_text") != "deterministic_extraction"
            or fact_boundary.get("core_conclusions")
            != "official_abstract_source_claim"
            or fact_boundary.get("model_inference") != "none"
            or fact_boundary.get("human_fulltext_review") != "not_completed"
        ):
            raise EvidenceBulkError(f"fulltext reading fact boundary conflicts: {source_id}")
        material_to_hash = {
            key: row[key]
            for key in (
                "schema_version",
                "source_candidate_id",
                "arxiv_id",
                "pdf_sha256",
                "pdf_bytes",
                "abstract_page_sha256",
                "analysis_payload",
            )
        }
        expected_hash = _sha256(canonical_json(material_to_hash).encode("utf-8"))
        if (
            row.get("reading_material_sha256") != expected_hash
            or row.get("provenance_urn")
            != f"qrh:evidence:fulltext-reading:{source_id}:sha256:{expected_hash}"
        ):
            raise EvidenceBulkError(f"fulltext reading material hash conflicts: {source_id}")
    return tuple(sorted(rows, key=lambda row: str(row["source_candidate_id"]))), _sha256(payload)


def verify_bulk_package(
    settings: Settings,
    package_root: Path,
    *,
    normalized_manifest_path: Path | None = None,
) -> VerifiedBulkPackage:
    settings.validate()
    root = package_root.absolute()
    try:
        ensure_no_reparse_components(root)
        info = root.lstat()
        root.relative_to(settings.project_root.resolve(strict=True))
    except (ConfigurationError, FileNotFoundError, OSError, ValueError) as error:
        raise EvidenceBulkError("bulk package must be a real directory inside project_root") from error
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise EvidenceBulkError("bulk package root is unsafe")
    reference_root = (settings.project_root / "reference").resolve(strict=True)
    try:
        root.resolve(strict=True).relative_to(reference_root)
    except ValueError:
        pass
    else:
        raise EvidenceBulkError("bulk preprocessing package must not be inside reference/**")

    artifacts, artifact_hash = _artifact_entries(root)
    required_artifacts = {
        "candidate_ledger.jsonl",
        "crossref_candidates.jsonl",
        "external_assertions.jsonl",
        "input_manifest.json",
        "network_attempts.jsonl",
        "resource_manifest.jsonl",
        "verification_report.json",
    }
    if not required_artifacts.issubset(artifacts):
        raise EvidenceBulkError("artifact manifest does not bind every required bulk input")

    input_payload = _read_regular(root / "input_manifest.json")
    input_manifest = _json_bytes(input_payload, label="input_manifest.json")
    if input_manifest.get("schema_version") != PACKAGE_SCHEMA_VERSION:
        raise EvidenceBulkError("unsupported bulk package schema")
    frozen_inputs = input_manifest.get("inputs")
    if not isinstance(frozen_inputs, list) or len(frozen_inputs) != 2:
        raise EvidenceBulkError("input manifest must bind exactly the candidates and occurrences inputs")
    occurrence_path: Path | None = None
    declared_input_paths: set[str] = set()
    for item in frozen_inputs:
        relative = str(item.get("path", ""))
        declared_input_paths.add(relative)
        source = _contained_path(settings.project_root, relative)
        payload = _read_regular(source)
        if len(payload) != item.get("bytes") or _sha256(payload) != item.get("sha256"):
            raise EvidenceBulkError(f"frozen E input changed: {relative}")
        if relative.endswith("/occurrences.jsonl"):
            occurrence_path = source
    expected_input_paths = {
        "project_state/workers/archive_paper_clues/candidates.json",
        "project_state/workers/archive_paper_clues/occurrences.jsonl",
    }
    if declared_input_paths != expected_input_paths or occurrence_path is None:
        raise EvidenceBulkError("input manifest paths differ from the approved E source pair")

    verification = _json_bytes(
        _read_regular(root / "verification_report.json"), label="verification_report.json"
    )
    checks = verification.get("checks") or {}
    if verification.get("overall") is not True or not checks or not all(checks.values()):
        raise EvidenceBulkError("E preprocessing verification report is not an exact PASS")

    source_payloads = {
        name: _read_regular(root / name)
        for name in (
            "candidate_ledger.jsonl",
            "crossref_candidates.jsonl",
            "external_assertions.jsonl",
            "network_attempts.jsonl",
            "resource_manifest.jsonl",
        )
    }
    source_file_hashes = {name: _sha256(payload) for name, payload in source_payloads.items()}
    candidates = _jsonl_bytes(
        source_payloads["candidate_ledger.jsonl"], label="candidate_ledger.jsonl"
    )
    occurrences = _jsonl_bytes(_read_regular(occurrence_path), label="occurrences.jsonl")
    crossref = _jsonl_bytes(
        source_payloads["crossref_candidates.jsonl"], label="crossref_candidates.jsonl"
    )
    assertions = _jsonl_bytes(
        source_payloads["external_assertions.jsonl"], label="external_assertions.jsonl"
    )
    network = _jsonl_bytes(
        source_payloads["network_attempts.jsonl"], label="network_attempts.jsonl"
    )
    candidate_ids = [str(row.get("candidate_id", "")) for row in candidates]
    linked = [row for row in occurrences if row.get("candidate_id")]
    unlinked = [row for row in occurrences if not row.get("candidate_id")]
    crossref_results = [result for search in crossref for result in search.get("results", [])]
    request_ids = [str(row.get("request_id", "")) for row in network]
    occurrence_ids = [str(row.get("occurrence_id", "")) for row in occurrences]
    if len(candidate_ids) != EXPECTED_CANDIDATES or len(set(candidate_ids)) != EXPECTED_CANDIDATES:
        raise EvidenceBulkError("candidate ledger is not the approved 245-row unique set")
    if any(str(row.get("schema_version")) != PACKAGE_SCHEMA_VERSION for row in candidates):
        raise EvidenceBulkError("candidate ledger contains an unsupported row schema")
    if (
        len(occurrences) != EXPECTED_LEDGER_ENTRIES
        or len(occurrence_ids) != len(set(occurrence_ids))
        or len(linked) != EXPECTED_LINKED_ENTRIES
        or len(unlinked) != EXPECTED_UNLINKED_ENTRIES
    ):
        raise EvidenceBulkError("occurrence ledger counts differ from the frozen E facts")
    if any(str(row.get("candidate_id")) not in set(candidate_ids) for row in linked):
        raise EvidenceBulkError("occurrence ledger links an unknown candidate")
    if (
        len(crossref) != EXPECTED_CROSSREF_SEARCHES
        or len(crossref_results) != EXPECTED_EXTERNAL_CANDIDATES
        or any(search.get("resolution_status") != "candidate_search_only_no_auto_merge" for search in crossref)
        or any(
            result.get("identity_decision") != "none_title_search_never_auto_merges"
            or result.get("assertion_kind") != "external_candidate_not_selected"
            for result in crossref_results
        )
    ):
        raise EvidenceBulkError("Crossref candidates are not the approved never-auto-select set")
    if len(assertions) != EXPECTED_EXTERNAL_ASSERTIONS or any(
        row.get("selection_status") != "not_canonicalized_by_this_preprocess"
        for row in assertions
    ):
        raise EvidenceBulkError("external assertion boundary is incomplete")
    if (
        len(network) != EXPECTED_NETWORK_ATTEMPTS
        or any(not value for value in request_ids)
        or len(request_ids) != len(set(request_ids))
    ):
        raise EvidenceBulkError("network attempt ledger is not the approved 204-row unique set")

    normalized_path = normalized_manifest_path or _default_normalized_manifest()
    resources, normalized_hash = verify_normalized_resource_manifest(
        root,
        normalized_path,
        artifact_entries=artifacts,
        artifact_manifest_hash=artifact_hash,
        candidates=candidates,
    )
    reading_path = normalized_path.with_name("fulltext_reading_results.jsonl")
    reading_results, reading_results_hash = _verify_fulltext_reading_results(
        root,
        reading_path,
        candidates=candidates,
        resources=resources,
    )
    source_set_hash = _sha256(
        canonical_json(
            {
                "declared_artifact_manifest_hash": artifact_hash,
                "frozen_input_manifest_hash": _sha256(input_payload),
                "normalized_resource_manifest_hash": normalized_hash,
                "fulltext_reading_results_hash": reading_results_hash,
                "source_file_hashes": source_file_hashes,
            }
        ).encode("utf-8")
    )
    return VerifiedBulkPackage(
        root=root,
        input_manifest_hash=_sha256(input_payload),
        artifact_manifest_hash=source_set_hash,
        declared_artifact_manifest_hash=artifact_hash,
        normalized_resource_manifest_hash=normalized_hash,
        fulltext_reading_results_hash=reading_results_hash,
        source_file_hashes=source_file_hashes,
        captured_at=str(input_manifest["captured_at"]),
        candidates=tuple(candidates),
        occurrences=tuple(occurrences),
        crossref_searches=tuple(crossref),
        external_assertions=tuple(assertions),
        network_attempts=tuple(network),
        resources=resources,
        reading_results=reading_results,
    )


def _candidate_material(
    row: dict[str, Any], canonicalized_source_ids: set[str]
) -> tuple[str, str, str, str]:
    local = row["local_claim"]
    identity_status = str(row["identity_status"])
    ambiguity = str(local.get("ambiguity_reason") or "")
    if identity_status == "not_applicable_method_or_resource_clue":
        return (
            "method_or_resource_family",
            "non_paper_resource",
            "rejected_non_paper",
            "rejected_non_paper",
        )
    if str(row["candidate_id"]) in canonicalized_source_ids:
        return ("paper_or_scholarly_work", "paper", "externally_verified", "verified")
    if "冲突" in ambiguity:
        return ("paper_or_scholarly_work", "paper", "conflicted", "conflicted")
    clue_status = (
        "resolution_pending"
        if identity_status == "unresolved_crossref_candidates_only"
        else "unresolved"
    )
    return ("paper_or_scholarly_work", "paper", clue_status, "proposed")


def _parse_year(value: object) -> int | None:
    text = str(value or "").strip()
    if re.fullmatch(r"(?:1[4-9]|20|21|22|23|24|25|26|27|28|29)[0-9]{2}", text):
        return int(text)
    return None


def _metadata_tokens(value: object) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", str(value or "").casefold()))


def _local_metadata_assertion_status(
    field_name: str,
    value: object,
    official: OfficialPaperMaterial | None,
) -> str:
    if official is None:
        return "claimed"
    if field_name == "title":
        return "claimed" if _metadata_tokens(value) == _metadata_tokens(official.title) else "conflicted"
    if field_name == "publication_year":
        return (
            "claimed"
            if int(value) == int(official.publication_date[:4])
            else "conflicted"
        )
    if field_name == "author":
        official_tokens = _metadata_tokens(" ".join(official.authors))
        return "claimed" if _metadata_tokens(value) == official_tokens else "conflicted"
    return "claimed"


def _request_candidate_id(request_id: str) -> str | None:
    match = _CANDIDATE_IN_REQUEST_RE.search(request_id)
    return match.group(1) if match else None


def _request_identity_hash(row: dict[str, Any]) -> str:
    material = {
        "request_id": row.get("request_id"),
        "request_url": row.get("request_url"),
        "request_attempt": row.get("request_attempt"),
        "started_at": row.get("started_at"),
    }
    return _sha256(canonical_json(material).encode("utf-8"))


def _network_status(row: dict[str, Any]) -> str:
    status = str(row.get("status", ""))
    if status == "success":
        required = ("final_url", "http_status", "mime_type", "bytes", "sha256")
        if any(row.get(field) is None for field in required):
            raise EvidenceBulkError(f"successful request is incomplete: {row.get('request_id')}")
        if not 200 <= int(row["http_status"]) <= 299:
            raise EvidenceBulkError(f"successful request is not 2xx: {row.get('request_id')}")
        return "succeeded"
    if status == "http_error":
        return "http_failed"
    if status in {"network_error", "request_error", "failed"}:
        return "network_failed"
    if status in {"not_attempted", "skipped"}:
        return "not_attempted"
    raise EvidenceBulkError(f"unsupported network attempt status: {status!r}")


def _network_rights(row: dict[str, Any]) -> tuple[str, str]:
    request_id = str(row["request_id"])
    url = str(row["request_url"])
    path = urlsplit(url).path.lower()
    if request_id.startswith("arxiv:pdf:") and path.startswith("/pdf/"):
        return (
            "repository_distribution_only",
            "specific-known-paper retrieval from official arXiv; per-paper license controls reuse",
        )
    if request_id.startswith("arxiv:"):
        return (
            "public_access_unknown_reuse",
            "official arXiv metadata or abstract-page observation; no reuse right inferred",
        )
    if request_id.startswith("crossref:"):
        return (
            "public_access_unknown_reuse",
            "public Crossref metadata lookup; search results are not identity selections",
        )
    if request_id.startswith("landing:"):
        return (
            "unknown",
            "public landing-page metadata observation only; full text was not requested",
        )
    if request_id.startswith("policy:"):
        return ("public_access_unknown_reuse", "public connector policy-page observation")
    return ("unknown", "audited preprocessing request; no access or reuse right inferred")


def _occurrence_kind(raw_type: str) -> str:
    if raw_type.startswith("strong_identifier") or raw_type == "explicit_url":
        return "strong_identifier"
    if raw_type.startswith("formal_"):
        return "formal_reference"
    if raw_type in {"method_or_resource_name", "non_paper_project_reference"}:
        return "method_or_resource_name"
    return "textual_mention"


def _canonical_occurrence_kind(source_path: str, raw_marker: str) -> str:
    """Canonical marker kind must not depend on a candidate-specific ledger row."""

    folded = raw_marker.casefold()
    if re.search(r"(?:arxiv\s*:|doi\s*:|https?://)", folded):
        return "strong_identifier"
    suffix = PurePosixPath(source_path).suffix.casefold()
    if suffix == ".bib" or re.search(r"\\cite|\\bibitem|\^src", raw_marker):
        return "formal_reference"
    return "textual_mention"


def _entry_status(
    occurrence: dict[str, Any],
    candidate_by_source_id: dict[str, dict[str, Any]],
    paper_ids: dict[str, str],
) -> tuple[str, str]:
    source_candidate_id = occurrence.get("candidate_id")
    if not source_candidate_id:
        return (
            "unresolved",
            "E occurrence is explicitly unlinked; no candidate or paper was invented",
        )
    candidate = candidate_by_source_id[str(source_candidate_id)]
    _, candidate_kind, clue_status, _ = _candidate_material(candidate, set(paper_ids))
    if candidate_kind == "non_paper_resource":
        return ("rejected_non_paper", "candidate is explicitly a method/resource clue")
    if str(source_candidate_id) in paper_ids:
        return (
            "resolved",
            "official arXiv abstract-page citation_arxiv_id resolves this candidate",
        )
    if clue_status == "conflicted":
        return ("conflicted", "archive-local candidate clues are explicitly conflicting")
    confirmation = str(candidate["local_claim"].get("confirmation_level", ""))
    if confirmation.startswith("L1_") or confirmation.startswith("L2_"):
        return (
            "source_only",
            "archive source occurrence is retained, but candidate identity is not canonicalized",
        )
    return (
        "unresolved",
        "archive source occurrence is retained pending identity disambiguation",
    )


def _line_material(payload: bytes) -> tuple[list[bytes], list[int]]:
    lines = payload.splitlines(keepends=True)
    offsets: list[int] = []
    current = 0
    for line in lines:
        offsets.append(current)
        current += len(line)
    if not lines and payload == b"":
        return [b""], [0]
    return lines, offsets


def _line_body(value: bytes) -> bytes:
    return value[:-2] if value.endswith(b"\r\n") else value[:-1] if value.endswith((b"\n", b"\r")) else value


def _exact_positions(haystack: bytes, needle: bytes) -> list[int]:
    if not needle:
        return []
    positions: list[int] = []
    start = 0
    while True:
        position = haystack.find(needle, start)
        if position < 0:
            return positions
        positions.append(position)
        start = position + len(needle)


def _parse_locator(value: str) -> tuple[int | None, int]:
    line_match = re.fullmatch(r"line:([0-9]+)", value)
    if line_match:
        return None, int(line_match.group(1))
    pdf_match = re.fullmatch(r"page:([0-9]+);line:([0-9]+)", value)
    if pdf_match:
        return int(pdf_match.group(1)), int(pdf_match.group(2))
    raise EvidenceBulkError(f"unsupported E locator: {value}")


def _prepare_citations(
    settings: Settings,
    package: VerifiedBulkPackage,
    clue_ids: dict[str, str],
    candidate_by_source_id: dict[str, dict[str, Any]],
    paper_ids: dict[str, str],
    provenance_urn: str,
) -> tuple[list[_CitationRow], int]:
    source_cache: dict[str, tuple[bytes, list[bytes], list[int]]] = {}
    canonical_by_id: dict[str, tuple[object, ...]] = {}
    rows: list[_CitationRow] = []
    archive_release_urn = f"qrh:archive:e-bulk-input:sha256:{package.input_manifest_hash}"

    for raw in package.occurrences:
        source_path = str(raw["source_path"])
        canonical_path = str(raw["canonical_path"])
        source_kind = str(raw["source_kind"])
        document_sha = str(raw["source_sha256"])
        claimed_page, claimed_line = _parse_locator(str(raw["locator"]))
        raw_marker = str(raw["original_clue"])
        marker_bytes = raw_marker.encode("utf-8")
        actual_line = claimed_line
        byte_start: int | None = None
        byte_end: int | None = None
        context_text = str(raw["context"])

        if source_kind == "utf8_project_text":
            if source_path not in source_cache:
                source = _contained_path(settings.archive_root, source_path)
                payload = _read_regular(source)
                if _sha256(payload) != document_sha:
                    raise EvidenceBulkError(f"archive source hash differs from E ledger: {source_path}")
                try:
                    payload.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise EvidenceBulkError(f"E UTF-8 source is not UTF-8: {source_path}") from error
                line_bytes, offsets = _line_material(payload)
                source_cache[source_path] = (payload, line_bytes, offsets)
            payload, line_bytes, offsets = source_cache[source_path]
            claimed_body = (
                _line_body(line_bytes[claimed_line - 1])
                if 1 <= claimed_line <= len(line_bytes)
                else None
            )
            claimed_positions = (
                _exact_positions(claimed_body, marker_bytes)
                if claimed_body is not None
                else []
            )
            if len(claimed_positions) == 1:
                line_position = claimed_positions[0]
                byte_start = offsets[actual_line - 1] + line_position
                byte_end = byte_start + len(marker_bytes)
                context_text = claimed_body.decode("utf-8")
                locator_kind = "utf8_bytes"
                locator = {
                    "actual_line": actual_line,
                    "claimed_line": claimed_line,
                    "match_ordinal": 1,
                }
                citation_id = citation_id_for_marker(
                    document_sha, byte_start, byte_end, raw_marker
                )
                if payload[byte_start:byte_end] != marker_bytes:
                    raise EvidenceBulkError("computed UTF-8 marker span failed byte verification")
            else:
                locator_kind = "source_locator_claim"
                if claimed_body is not None:
                    context_text = claimed_body.decode("utf-8")
                locator = {
                    "claimed_context": raw["context"],
                    "claimed_locator": raw["locator"],
                    "exact_match_count_on_claimed_line": len(claimed_positions),
                    "exact_match_offsets_on_claimed_line": claimed_positions,
                    "match_status": (
                        "ambiguous_multiple_exact_on_claimed_line"
                        if len(claimed_positions) > 1
                        else "not_exact_on_claimed_line"
                    ),
                    "source_path": source_path,
                }
                citation_id = citation_id_for_locator(
                    document_sha, locator_kind, locator, raw_marker
                )
        elif source_kind == "pdf_text_extraction":
            locator_kind = "pdf_extracted_page_line"
            locator = {
                "extraction_identity_sha256": document_sha,
                "line": claimed_line,
                "page": claimed_page,
                "source_path": source_path,
            }
            citation_id = citation_id_for_locator(
                document_sha, locator_kind, locator, raw_marker
            )
        else:
            raise EvidenceBulkError(f"unsupported E source kind: {source_kind}")

        source_candidate_id = str(raw.get("candidate_id") or "")
        clue_id = clue_ids.get(source_candidate_id) if source_candidate_id else None
        status, reason = _entry_status(raw, candidate_by_source_id, paper_ids)
        if locator_kind == "utf8_bytes":
            locator_status = "valid"
            canonical_reason = "exact UTF-8 source object and unique half-open byte span verified"
        elif locator.get("match_status") == "ambiguous_multiple_exact_on_claimed_line":
            locator_status = "unresolved"
            canonical_reason = (
                "claimed line contains multiple exact markers and the source supplies no ordinal"
            )
        else:
            locator_status = "source_only"
            canonical_reason = (
                "claimed line has no unique exact marker; cross-line fallback is forbidden"
            )
        canonical = (
            citation_id,
            document_sha,
            locator_kind,
            canonical_json(locator),
            actual_line,
            actual_line,
            byte_start,
            byte_end,
            raw_marker,
            _sha256(marker_bytes),
            context_text,
            _sha256(context_text.encode("utf-8")),
            _canonical_occurrence_kind(source_path, raw_marker),
            locator_status,
            canonical_reason,
            package.captured_at,
        )
        prior = canonical_by_id.setdefault(citation_id, canonical)
        if prior != canonical:
            differences = [
                (index, prior[index], canonical[index])
                for index in range(len(canonical))
                if prior[index] != canonical[index]
            ]
            raise EvidenceBulkError(
                f"shared source marker has conflicting canonical material: "
                f"{citation_id}; differences={differences[:3]!r}"
            )

        research_urn = f"qrh:archive:research:{raw['research_id']}"
        document_version_urn = f"qrh:archive:document-version:sha256:{document_sha}"
        source_object_urn = f"qrh:archive:source-object:sha256:{document_sha}"
        ledger_entry_id = str(raw["occurrence_id"])
        ledger = (
            ledger_entry_id,
            citation_id,
            clue_id,
            research_urn,
            archive_release_urn,
            document_version_urn,
            source_object_urn,
            source_path,
            canonical_path,
            str(raw["locator"]),
            str(raw["occurrence_type"]),
            str(raw["candidate_link_method"]),
            str(raw["evidence_strength"]),
            str(raw.get("identifier") or ""),
            status,
            reason,
            canonical_json(raw),
            package.captured_at,
        )
        resolved_paper = paper_ids.get(source_candidate_id) if status == "resolved" else None
        binding_id = stable_evidence_id(
            "bind", ledger_entry_id, resolved_paper or "", status, provenance_urn
        )
        event_id = stable_evidence_id("bevt", ledger_entry_id, binding_id, "1")
        binding = (
            binding_id,
            ledger_entry_id,
            resolved_paper,
            status,
            reason,
            provenance_urn,
            package.captured_at,
            event_id,
        )
        relation: tuple[object, ...] | None = None
        if resolved_paper is not None:
            relation_kind = (
                "formal_reference"
                if str(raw["occurrence_type"]).startswith("formal_")
                else "mentions"
            )
            relation_id = stable_evidence_id(
                "relation", ledger_entry_id, resolved_paper, relation_kind
            )
            relation = (
                relation_id,
                research_urn,
                document_version_urn,
                ledger_entry_id,
                citation_id,
                resolved_paper,
                relation_kind,
                provenance_urn,
                package.captured_at,
            )
        rows.append(_CitationRow(citation_id, canonical, ledger, binding, relation))
    return rows, len(canonical_by_id)


def _insert_official_paper_facts(
    connection: sqlite3.Connection,
    *,
    source_id: str,
    material: OfficialPaperMaterial,
    source_candidate: dict[str, Any],
    paper_id: str,
    paper_urn: str,
    candidate_id: str,
    clue_id: str,
    import_provenance_urn: str,
    now: str,
) -> str:
    source_provenance = (
        f"qrh:evidence:arxiv-abs:{material.arxiv_id}:sha256:{material.abstract_page_sha256}"
    )
    creation_event = stable_evidence_id("idevt", "paper-created/v1", paper_id)
    connection.execute(
        """
        INSERT INTO paper_identity_event(
            identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
            normalized_value,provenance_urn,payload_json,occurred_at
        ) VALUES(?,'paper_created',NULL,?,NULL,NULL,?,?,?)
        """,
        (
            creation_event,
            paper_id,
            source_provenance,
            canonical_json(
                {
                    "identity_key": f"arxiv:{material.arxiv_id}",
                    "identity_source": material.identity_source,
                    "paper_urn": paper_urn,
                }
            ),
            now,
        ),
    )
    connection.execute(
        "INSERT INTO paper(paper_id,canonical_urn,creation_event_id,created_at) VALUES(?,?,?,?)",
        (paper_id, paper_urn, creation_event, now),
    )
    identifier_assertion_id = stable_evidence_id(
        "iassert", paper_id, "arxiv", material.arxiv_id, source_provenance
    )
    connection.execute(
        """
        INSERT INTO paper_identifier_assertion(
            identifier_assertion_id,paper_id,candidate_id,scheme,raw_value,
            normalized_value,assertion_status,provenance_urn,asserted_at
        ) VALUES(?,?,?,'arxiv',?,?,'verified',?,?)
        """,
        (
            identifier_assertion_id,
            paper_id,
            candidate_id,
            material.arxiv_id,
            material.arxiv_id,
            source_provenance,
            now,
        ),
    )
    assign_event = stable_evidence_id(
        "idevt", "identifier-assigned/v1", "arxiv", material.arxiv_id, paper_id
    )
    connection.execute(
        """
        INSERT INTO paper_identity_event(
            identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
            normalized_value,provenance_urn,payload_json,occurred_at
        ) VALUES(?,'identifier_assigned',NULL,?,'arxiv',?,?,?,?)
        """,
        (
            assign_event,
            paper_id,
            material.arxiv_id,
            source_provenance,
            canonical_json(
                {
                    "assertion_id": identifier_assertion_id,
                    "identity_source": material.identity_source,
                }
            ),
            now,
        ),
    )
    connection.execute(
        """
        INSERT INTO identifier_assignment_projection(
            scheme,normalized_value,paper_id,source_event_id,revision,updated_at
        ) VALUES('arxiv',?,?,?,1,?)
        """,
        (material.arxiv_id, paper_id, assign_event, now),
    )
    connection.execute(
        """
        INSERT INTO paper_clue_candidate(
            clue_id,candidate_id,link_kind,evidence_json,linked_at
        ) VALUES(?,?,'external_resolution',?,?)
        """,
        (
            clue_id,
            candidate_id,
            canonical_json(
                {
                    "identifier": f"arxiv:{material.arxiv_id}",
                    "identity_source": material.identity_source,
                    "paper_id": paper_id,
                    "source_page_sha256": material.abstract_page_sha256,
                }
            ),
            now,
        ),
    )

    metadata = (
        ("title", material.title),
        ("publication_date", material.publication_date),
        ("author", list(material.authors)),
        ("abstract", material.abstract),
    )
    for field_name, value in metadata:
        value_json = canonical_json(value)
        assertion_id = stable_evidence_id(
            "massert", paper_id, candidate_id, field_name, value_json, source_provenance
        )
        connection.execute(
            """
            INSERT INTO metadata_assertion(
                assertion_id,paper_id,candidate_id,field_name,value_json,
                assertion_status,source_kind,provenance_urn,asserted_at
            ) VALUES(?,?,?,?,?,'verified','repository',?,?)
            """,
            (
                assertion_id,
                paper_id,
                candidate_id,
                field_name,
                value_json,
                source_provenance,
                now,
            ),
        )
        selection_id = stable_evidence_id(
            "msel", paper_id, field_name, assertion_id, source_provenance
        )
        connection.execute(
            """
            INSERT INTO canonical_metadata_selection(
                selection_id,paper_id,field_name,assertion_id,supersedes_selection_id,
                provenance_urn,selected_at
            ) VALUES(?,?,?,?,NULL,?,?)
            """,
            (selection_id, paper_id, field_name, assertion_id, source_provenance, now),
        )

    for order, name in enumerate(material.authors, start=1):
        person_id = stable_evidence_id("person", name.casefold(), source_provenance)
        connection.execute(
            "INSERT INTO person(person_id,display_name,orcid,provenance_urn) VALUES(?,?,NULL,?)",
            (person_id, name, source_provenance),
        )
        connection.execute(
            """
            INSERT INTO paper_authorship(paper_id,person_id,author_order,role,provenance_urn)
            VALUES(?,?,?,'author',?)
            """,
            (paper_id, person_id, order, source_provenance),
        )

    category_assertion_id = stable_evidence_id(
        "catassert", paper_id, CATEGORY_MAPPING_POLICY, source_provenance
    )
    source_categories = [
        {
            "code": subject.code,
            "display_name": subject.display_name,
            "is_primary": subject.is_primary,
        }
        for subject in material.subjects
    ]
    connection.execute(
        """
        INSERT INTO paper_category_assertion(
            category_assertion_id,paper_id,source_system,source_categories_json,
            primary_source_category,mapping_policy_version,assertion_status,
            provenance_urn,asserted_at
        ) VALUES(?,?,'arxiv',?,?,?,'verified_external',?,?)
        """,
        (
            category_assertion_id,
            paper_id,
            canonical_json(source_categories),
            material.subjects[0].code,
            CATEGORY_MAPPING_POLICY,
            source_provenance,
            now,
        ),
    )
    for category_key, display_name, is_primary in _classified_categories(material):
        category_id = stable_evidence_id("cat", category_key)
        connection.execute(
            """
            INSERT INTO paper_category(category_id,category_key,display_name)
            VALUES(?,?,?) ON CONFLICT(category_id) DO NOTHING
            """,
            (category_id, category_key, display_name),
        )
        actual_category = connection.execute(
            "SELECT category_key,display_name FROM paper_category WHERE category_id=?",
            (category_id,),
        ).fetchone()
        if actual_category is None or tuple(actual_category) != (category_key, display_name):
            raise EvidenceBulkError("paper category taxonomy identity conflicts")
        connection.execute(
            """
            INSERT INTO paper_category_assignment(
                paper_id,category_id,provenance_urn,assigned_at
            ) VALUES(?,?,?,?)
            """,
            (paper_id, category_id, source_provenance, now),
        )
        connection.execute(
            """
            INSERT INTO paper_category_assignment_detail(
                paper_id,category_id,provenance_urn,is_primary,category_assertion_id
            ) VALUES(?,?,?,?,?)
            """,
            (
                paper_id,
                category_id,
                source_provenance,
                int(is_primary),
                category_assertion_id,
            ),
        )

    institution_resolution_id = stable_evidence_id(
        "instres", paper_id, "official-arxiv-abs-affiliation-metadata-absent/v1", source_provenance
    )
    connection.execute(
        """
        INSERT INTO paper_institution_resolution(
            institution_resolution_id,paper_id,resolution_status,institutions_json,
            reason_code,reason_text,checked_source_fields_json,provenance_urn,resolved_at
        ) VALUES(?,?,'unresolved','[]',?,?,?,?,?)
        """,
        (
            institution_resolution_id,
            paper_id,
            "official_source_does_not_expose_affiliation_metadata",
            (
                "已核验的 arXiv 官方摘要页未提供可安全映射到作者的机构字段；"
                "在取得权威来源或完成全文人工核验前保持 unresolved。"
            ),
            canonical_json(list(_AFFILIATION_META_FIELDS)),
            source_provenance,
            now,
        ),
    )

    for kind, url in (
        ("landing", material.abstract_page_url),
        ("repository", f"https://arxiv.org/pdf/{material.arxiv_id}"),
    ):
        link_id = stable_evidence_id("link", paper_id, kind, url, source_provenance)
        connection.execute(
            """
            INSERT INTO paper_external_link(
                external_link_id,paper_id,candidate_id,link_kind,url,
                verification_status,provenance_urn,asserted_at
            ) VALUES(?,?,NULL,?,?,'verified',?,?)
            """,
            (link_id, paper_id, kind, url, source_provenance, now),
        )

    excerpt_id = stable_evidence_id(
        "excerpt", paper_id, "official-arxiv-abstract", _sha256(material.abstract.encode("utf-8"))
    )
    connection.execute(
        """
        INSERT INTO evidence_excerpt(
            excerpt_id,paper_id,resource_id,excerpt_text,locator_json,
            excerpt_sha256,provenance_urn,created_at
        ) VALUES(?,?,NULL,?,?,?,?,?)
        """,
        (
            excerpt_id,
            paper_id,
            material.abstract,
            canonical_json(
                {
                    "cache_path": material.abstract_cache_path,
                    "html_meta_name": "citation_abstract",
                    "page_sha256": material.abstract_page_sha256,
                    "url": material.abstract_page_url,
                }
            ),
            _sha256(material.abstract.encode("utf-8")),
            source_provenance,
            now,
        ),
    )
    conclusion_id = stable_evidence_id(
        "conclusion", paper_id, material.abstract, source_provenance
    )
    connection.execute(
        """
        INSERT INTO paper_core_conclusion(
            conclusion_id,paper_id,conclusion_text,fact_status,provenance_urn,created_at
        ) VALUES(?,?,?,'source_claim',?,?)
        """,
        (conclusion_id, paper_id, material.abstract, source_provenance, now),
    )
    connection.execute(
        """
        INSERT INTO paper_core_conclusion_evidence(
            conclusion_id,excerpt_id,claim_scope,verification_status,
            provenance_urn,linked_at
        ) VALUES(?,?,'official_abstract_verbatim',
                 'source_verified_not_fulltext_reviewed',?,?)
        """,
        (conclusion_id, excerpt_id, source_provenance, now),
    )
    analysis_id = stable_evidence_id(
        "analysis", paper_id, "official-abstract-extraction", source_provenance
    )
    local_claim = source_candidate.get("local_claim") or {}
    metadata_comparison = {
        "title": {
            "local": local_claim.get("title"),
            "official": material.title,
            "status": _local_metadata_assertion_status(
                "title", local_claim.get("title"), material
            ),
        },
        "publication_year": {
            "local": _parse_year(local_claim.get("year")),
            "official": int(material.publication_date[:4]),
            "status": _local_metadata_assertion_status(
                "publication_year", _parse_year(local_claim.get("year")) or 0, material
            ),
        },
        "authors": {
            "local": local_claim.get("authors"),
            "official": list(material.authors),
            "status": _local_metadata_assertion_status(
                "author", local_claim.get("authors"), material
            ),
        },
    }
    connection.execute(
        """
        INSERT INTO paper_analysis(
            analysis_id,paper_id,analysis_kind,analysis_text,fact_status,
            provenance_urn,created_at
        ) VALUES(? ,?,'metadata_review',?,'source_fact',?,?)
        """,
        (
            analysis_id,
            paper_id,
            canonical_json(
                {
                    "fact_boundary": (
                        "已逐字解析并复核官方 arXiv abs HTML 的 citation_abstract，"
                        "并仅将该逐字摘要登记为作者 source_claim；PDF 哈希可安全回放，"
                        "但尚未完成独立全文精读、结论提炼或机构人工核验。"
                    ),
                    "local_vs_official_metadata": metadata_comparison,
                }
            ),
            source_provenance,
            now,
        ),
    )
    return excerpt_id


def _insert_many_exact(
    connection: sqlite3.Connection,
    sql: str,
    rows: Iterable[tuple[object, ...]],
) -> None:
    connection.executemany(sql, rows)


def _existing_import(
    settings: Settings, package: VerifiedBulkPackage
) -> sqlite3.Row | None:
    with evidence_connection(settings) as connection:
        return connection.execute(
            """
            SELECT * FROM evidence_import_receipt
            WHERE input_manifest_hash=? AND artifact_manifest_hash=?
            """,
            (package.input_manifest_hash, package.artifact_manifest_hash),
        ).fetchone()


def _result_counts(connection: sqlite3.Connection) -> dict[str, int]:
    tables = (
        "paper_clue",
        "paper_candidate",
        "external_identity_candidate",
        "external_assertion",
        "paper",
        "paper_identifier_assertion",
        "paper_category",
        "paper_category_assignment",
        "paper_category_assertion",
        "paper_category_assignment_detail",
        "paper_core_conclusion",
        "paper_core_conclusion_evidence",
        "paper_institution_resolution",
        "organization",
        "person_affiliation_assertion",
        "paper_analysis",
        "evidence_excerpt",
        "paper_reading_task",
        "paper_reading_run",
        "paper_reading_conclusion_binding",
        "citation_occurrence",
        "citation_ledger_entry",
        "citation_binding",
        "fetch_attempt",
        "paper_resource",
        "research_paper_relation",
    )
    result = {
        table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
        for table in tables
    }
    result["unlinked_ledger_entry"] = int(
        connection.execute(
            "SELECT count(*) FROM citation_ledger_entry WHERE clue_id IS NULL"
        ).fetchone()[0]
    )
    return result


def _verify_imported_state(settings: Settings, package: VerifiedBulkPackage) -> dict[str, int]:
    store = EvidenceResourceStore(settings)
    with evidence_connection(settings) as connection:
        counts = _result_counts(connection)
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        crossref_selected = int(
            connection.execute(
                "SELECT count(*) FROM external_identity_candidate WHERE selection_status<>'not_selected'"
            ).fetchone()[0]
        )
        resource_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id"
            )
        ]
        linked = int(
            connection.execute(
                "SELECT count(*) FROM citation_ledger_entry WHERE clue_id IS NOT NULL"
            ).fetchone()[0]
        )
        missing_categories = int(
            connection.execute(
                """
                SELECT count(*) FROM paper
                WHERE NOT EXISTS (
                    SELECT 1 FROM paper_category_assignment AS assignment
                    WHERE assignment.paper_id=paper.paper_id
                )
                """
            ).fetchone()[0]
        )
        primary_category_violations = int(
            connection.execute(
                """
                SELECT count(*) FROM (
                    SELECT paper.paper_id,
                           sum(CASE WHEN detail.is_primary=1 THEN 1 ELSE 0 END) AS primary_count
                    FROM paper
                    LEFT JOIN paper_category_assignment_detail AS detail
                      ON detail.paper_id=paper.paper_id
                    GROUP BY paper.paper_id
                    HAVING primary_count<>1
                )
                """
            ).fetchone()[0]
        )
        conclusion_evidence_violations = int(
            connection.execute(
                """
                SELECT count(*)
                FROM paper_core_conclusion AS conclusion
                LEFT JOIN paper_core_conclusion_evidence AS link USING(conclusion_id)
                LEFT JOIN evidence_excerpt AS excerpt ON excerpt.excerpt_id=link.excerpt_id
                WHERE conclusion.fact_status<>'source_claim'
                   OR link.claim_scope<>'official_abstract_verbatim'
                   OR link.verification_status<>'source_verified_not_fulltext_reviewed'
                   OR conclusion.conclusion_text<>excerpt.excerpt_text
                   OR conclusion.provenance_urn<>excerpt.provenance_urn
                   OR link.provenance_urn<>excerpt.provenance_urn
                """
            ).fetchone()[0]
        )
        institution_resolution_violations = int(
            connection.execute(
                """
                SELECT count(*) FROM paper
                LEFT JOIN paper_institution_resolution AS resolution USING(paper_id)
                WHERE resolution.paper_id IS NULL
                   OR resolution.resolution_status<>'unresolved'
                   OR json_array_length(resolution.institutions_json)<>0
                   OR resolution.reason_code<>'official_source_does_not_expose_affiliation_metadata'
                """
            ).fetchone()[0]
        )
        catalog_contract_violations = int(
            connection.execute(
                """
                SELECT count(*) FROM paper_catalog_projection
                WHERE json_array_length(categories_json)=0
                   OR json_array_length(core_conclusions_json)<>1
                   OR json_extract(core_conclusions_json,'$[0].fact_status')<>'source_claim'
                   OR json_extract(core_conclusions_json,'$[0].claim_scope')<>'official_abstract_verbatim'
                """
            ).fetchone()[0]
        )
        reading_input_violations = int(
            connection.execute(
                """
                SELECT count(*) FROM paper_reading_run AS run
                JOIN paper_reading_task AS task USING(reading_task_id)
                WHERE run.input_snapshot_hash<>task.input_snapshot_hash
                """
            ).fetchone()[0]
        )
        pending_reading_tasks = int(
            connection.execute(
                """
                SELECT count(*) FROM paper_reading_task AS task
                WHERE NOT EXISTS (
                    SELECT 1 FROM paper_reading_run AS run
                    WHERE run.reading_task_id=task.reading_task_id
                      AND run.result_status='succeeded'
                )
                """
            ).fetchone()[0]
        )
        successful_readings = connection.execute(
            """
            SELECT identifier.normalized_value AS arxiv_id,
                   run.analysis_payload_json,run.provenance_urn,
                   run.attempt_number,binding.conclusion_id,
                   conclusion.paper_id AS conclusion_paper_id,task.paper_id
            FROM paper_reading_run AS run
            JOIN paper_reading_task AS task USING(reading_task_id)
            JOIN paper_identifier_assertion AS identifier
              ON identifier.paper_id=task.paper_id AND identifier.scheme='arxiv'
            LEFT JOIN paper_reading_conclusion_binding AS binding
              ON binding.reading_run_id=run.reading_run_id
            LEFT JOIN paper_core_conclusion AS conclusion
              ON conclusion.conclusion_id=binding.conclusion_id
            WHERE run.result_status='succeeded'
            ORDER BY identifier.normalized_value
            """
        ).fetchall()
        recovery_probe = connection.execute(
            """
            SELECT identifier.normalized_value AS arxiv_id,run.attempt_number,
                   run.result_status,run.failure_json,
                   (SELECT retry.attempt_number FROM paper_reading_run AS retry
                    WHERE retry.reading_task_id=run.reading_task_id
                      AND retry.result_status='succeeded') AS retry_attempt
            FROM paper_reading_run AS run
            JOIN paper_reading_task AS task USING(reading_task_id)
            JOIN paper_identifier_assertion AS identifier
              ON identifier.paper_id=task.paper_id AND identifier.scheme='arxiv'
            WHERE run.result_status='failed'
            """
        ).fetchall()
    expected = {
        "paper_clue": EXPECTED_CANDIDATES,
        "paper_candidate": EXPECTED_CANDIDATES,
        "external_identity_candidate": EXPECTED_EXTERNAL_CANDIDATES,
        "external_assertion": EXPECTED_EXTERNAL_ASSERTIONS,
        "paper": EXPECTED_RESOURCES,
        "paper_identifier_assertion": EXPECTED_RESOURCES,
        "paper_category": EXPECTED_PAPER_CATEGORIES,
        "paper_category_assignment": EXPECTED_CATEGORY_ASSIGNMENTS,
        "paper_category_assertion": EXPECTED_RESOURCES,
        "paper_category_assignment_detail": EXPECTED_CATEGORY_ASSIGNMENTS,
        "paper_core_conclusion": EXPECTED_CORE_CONCLUSIONS,
        "paper_core_conclusion_evidence": EXPECTED_CORE_CONCLUSIONS,
        "paper_institution_resolution": EXPECTED_INSTITUTION_RESOLUTIONS,
        "organization": 0,
        "person_affiliation_assertion": 0,
        "paper_analysis": EXPECTED_RESOURCES * 2,
        "evidence_excerpt": EXPECTED_RESOURCES,
        "paper_reading_task": EXPECTED_RESOURCES,
        "paper_reading_run": EXPECTED_READING_RUNS,
        "paper_reading_conclusion_binding": EXPECTED_SUCCESSFUL_READING_RUNS,
        "citation_occurrence": EXPECTED_CANONICAL_MARKERS,
        "citation_ledger_entry": EXPECTED_LEDGER_ENTRIES,
        "citation_binding": EXPECTED_LEDGER_ENTRIES,
        "fetch_attempt": EXPECTED_NETWORK_ATTEMPTS + 17,
        "paper_resource": EXPECTED_RESOURCES,
        "unlinked_ledger_entry": EXPECTED_UNLINKED_ENTRIES,
    }
    for key, value in expected.items():
        if counts.get(key) != value:
            raise EvidenceBulkError(
                f"imported {key} count differs from approved value: {counts.get(key)} != {value}"
            )
    if linked != EXPECTED_LINKED_ENTRIES or crossref_selected != 0:
        raise EvidenceBulkError("linked count or Crossref never-select invariant failed")
    if (
        missing_categories
        or primary_category_violations
        or conclusion_evidence_violations
        or institution_resolution_violations
        or catalog_contract_violations
        or reading_input_violations
        or pending_reading_tasks
    ):
        raise EvidenceBulkError(
            "paper minimum-field provenance or explicit-unknown contract failed"
        )
    expected_readings = {
        str(row["arxiv_id"]): row for row in package.reading_results
    }
    if len(successful_readings) != EXPECTED_SUCCESSFUL_READING_RUNS:
        raise EvidenceBulkError("successful fulltext reading run count is incomplete")
    for row in successful_readings:
        expected_reading = expected_readings.get(str(row["arxiv_id"]))
        if (
            expected_reading is None
            or str(row["analysis_payload_json"])
            != canonical_json(expected_reading["analysis_payload"])
            or str(row["provenance_urn"]) != str(expected_reading["provenance_urn"])
            or row["conclusion_id"] is None
            or row["conclusion_paper_id"] != row["paper_id"]
        ):
            raise EvidenceBulkError("fulltext reading result is not input-bound to its paper")
    if len(recovery_probe) != 1:
        raise EvidenceBulkError("controlled failed-to-retry recovery evidence is incomplete")
    failure = json.loads(str(recovery_probe[0]["failure_json"]))
    if (
        recovery_probe[0]["arxiv_id"] != "2002.08709"
        or recovery_probe[0]["attempt_number"] != 1
        or recovery_probe[0]["retry_attempt"] != 2
        or failure.get("class") != "controlled_recovery_probe"
    ):
        raise EvidenceBulkError("controlled failed-to-retry recovery sequence conflicts")
    if integrity != "ok" or foreign_keys:
        raise EvidenceBulkError("research_papers database integrity verification failed")
    for resource_id in resource_ids:
        store.resource_response(resource_id)
    if len(resource_ids) != EXPECTED_RESOURCES:
        raise EvidenceBulkError("verified local resource count differs from normalized manifest")
    return counts


def import_bulk_evidence(
    settings: Settings,
    package_root: Path,
    *,
    normalized_manifest_path: Path | None = None,
) -> BulkImportResult:
    """全量导入 245 candidates / 5,181 ledger entries / 18 audited PDFs。"""

    package = verify_bulk_package(
        settings,
        package_root,
        normalized_manifest_path=normalized_manifest_path,
    )
    initialize_evidence_database(settings)
    receipt_id = stable_evidence_id(
        "eimport",
        IMPORT_SCHEMA_VERSION,
        package.input_manifest_hash,
        package.artifact_manifest_hash,
        package.normalized_resource_manifest_hash,
    )
    existing = _existing_import(settings, package)
    if existing is not None:
        report = json.loads(str(existing["report_json"]))
        if (
            existing["import_receipt_id"] != receipt_id
            or report.get("normalized_resource_manifest_hash")
            != package.normalized_resource_manifest_hash
        ):
            raise EvidenceConflict("bulk import receipt conflicts with verified package")
        counts = _verify_imported_state(settings, package)
        inventory = export_inventory(settings)
        candidate_inventory = export_candidate_inventory(settings)
        return BulkImportResult(
            receipt_id,
            False,
            counts,
            inventory,
            candidate_inventory,
            EvidenceRepository(settings).snapshot_hash(),
            package.normalized_resource_manifest_hash,
        )

    with evidence_connection(settings) as connection:
        occupied = sum(
            int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in ("paper_clue", "paper_candidate", "citation_ledger_entry", "paper_resource")
        )
    if occupied:
        raise EvidenceBulkError("bulk import requires an empty Evidence business dataset")

    provenance_urn = f"qrh:evidence:bulk-package:sha256:{package.artifact_manifest_hash}"
    candidate_by_source_id = {
        str(row["candidate_id"]): row for row in package.candidates
    }
    clue_ids = {
        source_id: stable_evidence_id("clue", "archive-ledger/v1", source_id)
        for source_id in candidate_by_source_id
    }
    candidate_ids = {
        source_id: stable_evidence_id(
            "pcand", "archive-resolution/v1", source_id, provenance_urn
        )
        for source_id in candidate_by_source_id
    }
    official_materials = {
        str(resource["candidate_id"]): _official_paper_material(
            package.root,
            candidate_by_source_id[str(resource["candidate_id"])],
            candidate_id=str(resource["candidate_id"]),
            arxiv_id=str(resource["arxiv_id_claim"]),
        )
        for resource in package.resources
    }
    if len(official_materials) != EXPECTED_RESOURCES:
        raise EvidenceBulkError("official arXiv identity replay did not yield 18 unique papers")
    paper_ids = {
        source_id: stable_evidence_id(
            "paper", "canonical-paper/v1", f"arxiv:{material.arxiv_id}"
        )
        for source_id, material in official_materials.items()
    }
    paper_urns = {
        source_id: f"qrh:evidence:paper:{paper_id}"
        for source_id, paper_id in paper_ids.items()
    }
    reading_result_by_source = {
        str(row["source_candidate_id"]): row for row in package.reading_results
    }
    if set(reading_result_by_source) != set(paper_ids):
        raise EvidenceBulkError("fulltext reading result set differs from canonical paper set")

    store = EvidenceResourceStore(settings)
    staged: dict[str, StagedPdf] = {}
    for resource in package.resources:
        candidate_id = str(resource["candidate_id"])
        artifact_path = _contained_path(
            package.root, str(resource["artifact"]["local_path"])
        )
        staged_pdf = store.put_pdf(_read_regular(artifact_path))
        if (
            staged_pdf.content_sha256 != resource["payload"]["sha256"]
            or staged_pdf.bytes != resource["payload"]["bytes"]
        ):
            raise EvidenceBulkError(f"staged PDF differs from normalized manifest: {candidate_id}")
        staged[candidate_id] = staged_pdf

    citation_rows, canonical_marker_count = _prepare_citations(
        settings,
        package,
        clue_ids,
        candidate_by_source_id,
        paper_ids,
        provenance_urn,
    )
    if canonical_marker_count != EXPECTED_CANONICAL_MARKERS:
        raise EvidenceBulkError(
            f"canonical source-marker count differs: {canonical_marker_count} != {EXPECTED_CANONICAL_MARKERS}"
        )

    now = package.captured_at
    with evidence_connection(settings) as connection, immediate_transaction(connection):
        for source_id, row in sorted(candidate_by_source_id.items()):
            local = row["local_claim"]
            entity_kind, candidate_kind, clue_status, candidate_status = _candidate_material(
                row, set(paper_ids)
            )
            connection.execute(
                """
                INSERT INTO paper_clue(
                    clue_id,source_candidate_id,entity_kind,domain_category,raw_claim_json,
                    provenance_urn,resolution_status,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    clue_ids[source_id],
                    source_id,
                    entity_kind,
                    str(local.get("domain_category") or "") or None,
                    canonical_json(local),
                    provenance_urn,
                    clue_status,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO paper_candidate(
                    candidate_id,candidate_kind,title_claim,publication_year,
                    resolution_status,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    candidate_ids[source_id],
                    candidate_kind,
                    str(local.get("title") or "") or None,
                    _parse_year(local.get("year")),
                    candidate_status,
                    provenance_urn,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO paper_clue_candidate(
                    clue_id,candidate_id,link_kind,evidence_json,linked_at
                ) VALUES(?,?,'local_claim',?,?)
                """,
                (
                    clue_ids[source_id],
                    candidate_ids[source_id],
                    canonical_json(
                        {
                            "confirmation_level": local.get("confirmation_level"),
                            "fact_grade": row.get("local_claim_fact_grade"),
                            "identity_status": row.get("identity_status"),
                        }
                    ),
                    now,
                ),
            )
            for field_name, value in (
                ("title", local.get("title")),
                ("publication_year", _parse_year(local.get("year"))),
                ("author", local.get("authors")),
                ("venue", local.get("venue_or_publisher")),
                ("external_url", local.get("url")),
            ):
                if value in (None, ""):
                    continue
                assertion_id = stable_evidence_id(
                    "massert",
                    "",
                    candidate_ids[source_id],
                    field_name,
                    canonical_json(value),
                    provenance_urn,
                )
                assertion_status = _local_metadata_assertion_status(
                    field_name, value, official_materials.get(source_id)
                )
                connection.execute(
                    """
                    INSERT INTO metadata_assertion(
                        assertion_id,paper_id,candidate_id,field_name,value_json,
                        assertion_status,source_kind,provenance_urn,asserted_at
                    ) VALUES(?,NULL,?,?,?,?, 'archive_local',?,?)
                    """,
                    (
                        assertion_id,
                        candidate_ids[source_id],
                        field_name,
                        canonical_json(value),
                        assertion_status,
                        provenance_urn,
                        now,
                    ),
                )

        for search in package.crossref_searches:
            source_id = str(search["candidate_id"])
            request = search["request"]
            for result in search["results"]:
                rank = int(result["provider_rank"])
                provider = str(result["provider"])
                record = result["provider_record"]
                external_id = stable_evidence_id(
                    "extcand", source_id, provider, str(rank), str(request["request_id"])
                )
                connection.execute(
                    """
                    INSERT INTO external_identity_candidate(
                        external_candidate_id,candidate_id,provider,provider_rank,
                        provider_score,provider_record_json,selection_status,
                        identity_decision,provenance_urn,observed_at
                    ) VALUES(?,?,?,?,?,?,'not_selected',?,?,?)
                    """,
                    (
                        external_id,
                        candidate_ids[source_id],
                        provider,
                        rank,
                        float(record["score"]) if record.get("score") is not None else None,
                        canonical_json(record),
                        str(result["identity_decision"]),
                        f"{provenance_urn}:request:{request['request_id']}",
                        str(request.get("retrieved_at") or now),
                    ),
                )

        for assertion in package.external_assertions:
            source_id = str(assertion["subject_candidate_id"])
            connection.execute(
                """
                INSERT INTO external_assertion(
                    external_assertion_id,candidate_id,assertion_kind,field_name,value_json,
                    verification_status,selection_status,provenance_urn,asserted_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(assertion["assertion_id"]),
                    candidate_ids[source_id],
                    str(assertion["assertion_kind"]),
                    str(assertion["field_name"]),
                    canonical_json(assertion["value"]),
                    str(assertion["verification_status"]),
                    str(assertion["selection_status"]),
                    str(assertion["source_uri"]),
                    str(assertion["retrieved_at"]),
                ),
            )

        excerpt_ids: dict[str, str] = {}
        for source_id, material in sorted(official_materials.items()):
            excerpt_ids[source_id] = _insert_official_paper_facts(
                connection,
                source_id=source_id,
                material=material,
                source_candidate=candidate_by_source_id[source_id],
                paper_id=paper_ids[source_id],
                paper_urn=paper_urns[source_id],
                candidate_id=candidate_ids[source_id],
                clue_id=clue_ids[source_id],
                import_provenance_urn=provenance_urn,
                now=now,
            )

        network_by_request: dict[str, dict[str, Any]] = {}
        for network in package.network_attempts:
            request_id = str(network["request_id"])
            network_by_request[request_id] = network
            source_id = _request_candidate_id(request_id)
            internal_candidate = candidate_ids.get(source_id) if source_id else None
            linked_paper = paper_ids.get(source_id) if source_id else None
            result_status = _network_status(network)
            rights_status, legal_basis = _network_rights(network)
            fetch_id = stable_evidence_id("fetch", "fetch-attempt/v1", request_id)
            connection.execute(
                """
                INSERT INTO fetch_attempt(
                    fetch_attempt_id,source_request_id,subject_urn,paper_id,candidate_id,
                    requested_url,redirect_chain_json,final_url,http_status,response_mime,
                    response_bytes,response_sha256,request_identity_hash,rights_status,
                    legal_basis,result_status,error_class,error_detail,attempted_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    fetch_id,
                    request_id,
                    linked_paper and paper_urns[str(source_id)]
                    or internal_candidate and f"qrh:evidence:candidate:{internal_candidate}"
                    or f"qrh:evidence:network-request:{fetch_id}",
                    linked_paper,
                    internal_candidate,
                    str(network["request_url"]),
                    canonical_json([]),
                    network.get("final_url"),
                    network.get("http_status"),
                    network.get("mime_type"),
                    network.get("bytes"),
                    network.get("sha256"),
                    _request_identity_hash(network),
                    rights_status,
                    legal_basis,
                    result_status,
                    network.get("error_class"),
                    None,
                    str(
                        network.get("attempted_at")
                        or network.get("retrieved_at")
                        or network.get("started_at")
                        or now
                    ),
                ),
            )

        resource_ids: dict[str, str] = {}
        for resource in package.resources:
            source_id = str(resource["candidate_id"])
            normalized_request_id = f"recovered:arxiv:pdf:{source_id}"
            linked_paper = paper_ids[source_id]
            if source_id == "P073":
                request_id = "arxiv:pdf:P073"
                audit = network_by_request.get(request_id)
                if audit is None or audit.get("sha256") != resource["payload"]["sha256"]:
                    raise EvidenceBulkError("P073 primary request audit does not match its PDF")
            else:
                request_id = normalized_request_id
                request = resource["request"]
                fetch_id = stable_evidence_id("fetch", "fetch-attempt/v1", request_id)
                connection.execute(
                    """
                    INSERT INTO fetch_attempt(
                        fetch_attempt_id,source_request_id,subject_urn,paper_id,candidate_id,
                        requested_url,redirect_chain_json,final_url,http_status,response_mime,
                        response_bytes,response_sha256,request_identity_hash,rights_status,
                        legal_basis,result_status,error_class,error_detail,attempted_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'repository_distribution_only',
                             ?,'succeeded',NULL,?,?)
                    """,
                    (
                        fetch_id,
                        request_id,
                        paper_urns[source_id],
                        linked_paper,
                        candidate_ids[source_id],
                        str(request["request_url"]),
                        canonical_json([]),
                        str(request["final_url"]),
                        200,
                        "application/pdf",
                        int(resource["payload"]["bytes"]),
                        str(resource["payload"]["sha256"]),
                        _sha256(canonical_json(resource["cache_metadata"]).encode("utf-8")),
                        (
                            "recovered from audited cache metadata plus artifact manifest; "
                            "resource recovery does not drive identity; official abs-page ID does"
                        ),
                        canonical_json(
                            {
                                "lineage": resource["lineage"],
                                "normalized_manifest_hash": package.normalized_resource_manifest_hash,
                            }
                        ),
                        str(request["retrieved_at"]),
                    ),
                )
            fetch_id = stable_evidence_id("fetch", "fetch-attempt/v1", request_id)
            staged_pdf = staged[source_id]
            resource_id = stable_evidence_id(
                "res", "paper-resource/v1", staged_pdf.content_sha256
            )
            connection.execute(
                """
                INSERT INTO paper_resource(
                    resource_id,paper_id,candidate_id,fetch_attempt_id,resource_kind,
                    media_type,content_sha256,bytes,relative_path,rights_status,
                    verification_status,acquired_at
                ) VALUES(?,?,?,?,'paper_pdf','application/pdf',?,?,?,
                         'repository_distribution_only','verified',?)
                """,
                (
                    resource_id,
                    linked_paper,
                    candidate_ids[source_id],
                    fetch_id,
                    staged_pdf.content_sha256,
                    staged_pdf.bytes,
                    staged_pdf.relative_path,
                    str(resource["request"]["retrieved_at"]),
                ),
            )
            resource_ids[source_id] = resource_id
        if set(resource_ids) != set(paper_ids):
            raise EvidenceBulkError("not every canonical arXiv paper has one normalized PDF")

        for source_id, material in sorted(official_materials.items()):
            current_paper_id = paper_ids[source_id]
            current_resource_id = resource_ids[source_id]
            authors_json = [
                {"name": name, "affiliations": []} for name in material.authors
            ]
            categories = [
                display_name
                for _, display_name, _ in _classified_categories(material)
            ]
            source_provenance = (
                f"qrh:evidence:arxiv-abs:{material.arxiv_id}:"
                f"sha256:{material.abstract_page_sha256}"
            )
            core_conclusions = [
                {
                    "text": material.abstract,
                    "fact_status": "source_claim",
                    "claim_scope": "official_abstract_verbatim",
                    "verification_status": "source_verified_not_fulltext_reviewed",
                    "provenance_urn": source_provenance,
                }
            ]
            external_links = [
                {
                    "kind": "landing",
                    "url": material.abstract_page_url,
                    "verification_status": "verified",
                },
                {
                    "kind": "repository",
                    "url": f"https://arxiv.org/pdf/{material.arxiv_id}",
                    "verification_status": "verified",
                },
            ]
            local_resources = [
                {
                    "resource_id": current_resource_id,
                    "url": f"/api/v1/evidence/resources/{current_resource_id}",
                    "sha256": staged[source_id].content_sha256,
                    "bytes": staged[source_id].bytes,
                }
            ]
            connection.execute(
                """
                INSERT INTO paper_catalog_projection(
                    paper_id,title,publication_date,authors_json,institutions_json,
                    categories_json,core_conclusions_json,external_links_json,
                    local_resources_json,verification_status,projection_revision,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,'partial',1,?)
                """,
                (
                    current_paper_id,
                    material.title,
                    material.publication_date,
                    canonical_json(authors_json),
                    canonical_json([]),
                    canonical_json(categories),
                    canonical_json(core_conclusions),
                    canonical_json(external_links),
                    canonical_json(local_resources),
                    now,
                ),
            )
            input_snapshot_hash = _sha256(
                canonical_json(
                    {
                        "abstract_page_sha256": material.abstract_page_sha256,
                        "abstract_sha256": _sha256(material.abstract.encode("utf-8")),
                        "pdf_bytes": staged[source_id].bytes,
                        "pdf_sha256": staged[source_id].content_sha256,
                    }
                ).encode("utf-8")
            )
            task_id = stable_evidence_id(
                "readtask", current_paper_id, input_snapshot_hash
            )
            connection.execute(
                """
                INSERT INTO paper_reading_task(
                    reading_task_id,paper_id,resource_id,abstract_excerpt_id,
                    input_snapshot_hash,objective_text,required_outputs_json,
                    provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    current_paper_id,
                    current_resource_id,
                    excerpt_ids[source_id],
                    input_snapshot_hash,
                    (
                        "基于已复核 PDF 与官方摘要完成独立全文精读；区分来源事实、"
                        "模型推断和人审结论，并提炼可回指页码的核心结论。"
                    ),
                    canonical_json(
                        {
                            "analysis": "required",
                            "core_conclusions": "required_with_source_locators",
                            "fact_boundary": "required",
                        }
                    ),
                    provenance_urn,
                    now,
                ),
            )

            reading_result = reading_result_by_source[source_id]
            success_provenance = str(reading_result["provenance_urn"])
            success_attempt = 1
            if source_id == "P007":
                failure_provenance = (
                    f"{provenance_urn}:reading-recovery-probe:P007:attempt:1"
                )
                failure_key = "bulk-reading-recovery-probe:P007:attempt:1"
                failure_run_id = stable_evidence_id(
                    "readrun", task_id, failure_key, failure_provenance
                )
                connection.execute(
                    """
                    INSERT INTO paper_reading_run(
                        reading_run_id,reading_task_id,attempt_number,idempotency_key,
                        worker_kind,input_snapshot_hash,result_status,
                        analysis_payload_json,failure_json,provenance_urn,completed_at
                    ) VALUES(?,?,1,?,'external',?,'failed',NULL,?,?,?)
                    """,
                    (
                        failure_run_id,
                        task_id,
                        failure_key,
                        input_snapshot_hash,
                        canonical_json(
                            {
                                "class": "controlled_recovery_probe",
                                "reason": (
                                    "受控验证探针：证明失败 attempt 以追加新 run 恢复，"
                                    "不表示源 PDF 或正式全文读取发生真实故障。"
                                ),
                                "retry_policy": "append_new_attempt_without_mutating_history",
                            }
                        ),
                        failure_provenance,
                        now,
                    ),
                )
                success_attempt = 2

            success_key = (
                f"bulk-fulltext-reading:{source_id}:"
                f"sha256:{reading_result['reading_material_sha256']}"
            )
            success_run_id = stable_evidence_id(
                "readrun", task_id, success_key, success_provenance
            )
            connection.execute(
                """
                INSERT INTO paper_reading_run(
                    reading_run_id,reading_task_id,attempt_number,idempotency_key,
                    worker_kind,input_snapshot_hash,result_status,
                    analysis_payload_json,failure_json,provenance_urn,completed_at
                ) VALUES(?,?,?,?, 'external',?,'succeeded',?,NULL,?,?)
                """,
                (
                    success_run_id,
                    task_id,
                    success_attempt,
                    success_key,
                    input_snapshot_hash,
                    canonical_json(reading_result["analysis_payload"]),
                    success_provenance,
                    now,
                ),
            )
            reading_analysis_id = stable_evidence_id(
                "analysis", current_paper_id, "fulltext-reading-result/v1", success_provenance
            )
            connection.execute(
                """
                INSERT INTO paper_analysis(
                    analysis_id,paper_id,analysis_kind,analysis_text,fact_status,
                    provenance_urn,created_at
                ) VALUES(?,?,'reading_note',?,'source_fact',?,?)
                """,
                (
                    reading_analysis_id,
                    current_paper_id,
                    canonical_json(reading_result["analysis_payload"]),
                    success_provenance,
                    now,
                ),
            )
            conclusion_id = stable_evidence_id(
                "conclusion", current_paper_id, material.abstract, source_provenance
            )
            connection.execute(
                """
                INSERT INTO paper_reading_conclusion_binding(
                    reading_run_id,conclusion_id,provenance_urn,linked_at
                ) VALUES(?,?,?,?)
                """,
                (success_run_id, conclusion_id, success_provenance, now),
            )

        unique_occurrences = {row.citation_id: row.canonical for row in citation_rows}
        _insert_many_exact(
            connection,
            """
            INSERT INTO citation_occurrence(
                citation_id,document_sha256,locator_kind,locator_json,line_start,line_end,
                byte_start,byte_end,raw_marker_text,raw_marker_sha256,context_text,
                context_sha256,occurrence_kind,locator_status,status_reason,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            unique_occurrences.values(),
        )
        _insert_many_exact(
            connection,
            """
            INSERT INTO citation_ledger_entry(
                ledger_entry_id,citation_id,clue_id,research_urn,archive_release_urn,
                document_version_urn,source_object_urn,source_path,canonical_path,
                locator_claim,occurrence_type,candidate_link_method,evidence_strength,
                identifier_claim,entry_status,entry_reason,raw_payload_json,imported_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (row.ledger for row in citation_rows),
        )
        for row in citation_rows:
            (
                binding_id,
                ledger_entry_id,
                linked_paper,
                status,
                rationale,
                binding_provenance,
                created_at,
                event_id,
            ) = row.binding
            connection.execute(
                """
                INSERT INTO citation_binding(
                    binding_id,ledger_entry_id,paper_id,binding_status,rationale,
                    provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    binding_id,
                    ledger_entry_id,
                    linked_paper,
                    status,
                    rationale,
                    binding_provenance,
                    created_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO citation_binding_event(
                    binding_event_id,ledger_entry_id,binding_id,event_kind,
                    supersedes_event_id,provenance_urn,occurred_at
                ) VALUES(?,?,?,'binding_created',NULL,?,?)
                """,
                (event_id, ledger_entry_id, binding_id, binding_provenance, created_at),
            )
            connection.execute(
                """
                INSERT INTO citation_binding_projection(
                    ledger_entry_id,binding_id,source_event_id,revision,updated_at
                ) VALUES(?,?,?,1,?)
                """,
                (ledger_entry_id, binding_id, event_id, created_at),
            )
            if row.relation is not None:
                connection.execute(
                    """
                    INSERT INTO research_paper_relation(
                        relation_id,research_urn,document_version_urn,ledger_entry_id,
                        citation_id,paper_id,relation_kind,provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    row.relation,
                )

        report = {
            "schema_version": IMPORT_SCHEMA_VERSION,
            "artifact_manifest_hash": package.artifact_manifest_hash,
            "input_manifest_hash": package.input_manifest_hash,
            "normalized_resource_manifest_hash": package.normalized_resource_manifest_hash,
            "counts": {
                "candidates": EXPECTED_CANDIDATES,
                "canonical_source_markers": canonical_marker_count,
                "ledger_entries": EXPECTED_LEDGER_ENTRIES,
                "linked_entries": EXPECTED_LINKED_ENTRIES,
                "unlinked_entries": EXPECTED_UNLINKED_ENTRIES,
                "crossref_candidates_not_selected": EXPECTED_EXTERNAL_CANDIDATES,
                "network_attempts": EXPECTED_NETWORK_ATTEMPTS,
                "recovered_fetch_audits": 17,
                "resources": EXPECTED_RESOURCES,
                "canonical_papers": EXPECTED_RESOURCES,
                "official_abstract_excerpts": EXPECTED_RESOURCES,
                "paper_categories": EXPECTED_PAPER_CATEGORIES,
                "paper_category_assignments": EXPECTED_CATEGORY_ASSIGNMENTS,
                "official_abstract_source_claims": EXPECTED_CORE_CONCLUSIONS,
                "explicit_institution_resolutions": EXPECTED_INSTITUTION_RESOLUTIONS,
                "fulltext_reading_tasks": EXPECTED_RESOURCES,
                "fulltext_reading_runs": EXPECTED_READING_RUNS,
                "successful_fulltext_reading_runs": EXPECTED_SUCCESSFUL_READING_RUNS,
                "controlled_recovery_probe_failures": 1,
                "pending_full_reading_tasks": 0,
            },
            "resource_lineage": {
                "primary_manifest_and_audited_artifact": 1,
                "recovered_from_audited_artifact": 17,
            },
            "occurrence_contract": {
                "equations": [
                    "3983 uniquely located utf8 ledger entries -> 3432 exact citation_occurrence (551 shared)",
                    "763 source_locator_claim entries -> 763 path-scoped citation_occurrence (657 no exact marker; 106 ambiguous without ordinal)",
                    "435 PDF extraction locator entries -> 435 path-scoped citation_occurrence",
                    "3432 + 763 + 435 = 4630 citation_occurrence",
                    "4630 + 551 shared ledger rows = 5181 ledger entries",
                ],
                "utf8_dedup_key": (
                    "document_sha256 + byte_start + byte_end + raw_marker_sha256"
                ),
                "source_only_dedup_key": (
                    "document_sha256 + locator_kind + source_path + locator + raw_marker_sha256"
                ),
                "rejected_counts": {
                    "4449": (
                        "would collapse 138 path-scoped source-only/PDF aliases without raw-byte proof"
                    ),
                    "4528": (
                        "obsolete intermediate count without a deterministic locator key"
                    ),
                    "4587": (
                        "rejected because cross-line fallback and missing ordinals falsely upgraded 139 ledger rows"
                    ),
                },
            },
            "fact_boundaries": {
                "crossref_auto_selected": 0,
                "canonical_papers": EXPECTED_RESOURCES,
                "resource_identity_upgrades": 0,
                "strong_identity_sources": {
                    "official_arxiv_api_and_abstract_page": 1,
                    "official_arxiv_abstract_page_metadata_fallback": 17,
                },
                "category_mapping_policy": CATEGORY_MAPPING_POLICY,
                "core_conclusion_scope": "official_abstract_verbatim",
                "core_conclusion_fact_status": "source_claim",
                "fulltext_reading_runs": EXPECTED_SUCCESSFUL_READING_RUNS,
                "fulltext_reading_result_sha256": package.fulltext_reading_results_hash,
                "fulltext_reading_scope": (
                    "逐页确定性文本抽取与文档身份覆盖核验；可发布核心结论仍严格限于"
                    "官方摘要逐字 source_claim，不宣称已完成人工全文结论审核。"
                ),
                "controlled_recovery_probe": {
                    "failed_attempts": 1,
                    "successful_retry_attempts": 1,
                    "source_candidate_id": "P007",
                    "meaning": "仅验证 append-only 失败恢复协议，不表示源材料真实故障",
                },
                "institution_resolution": {
                    "unresolved": EXPECTED_INSTITUTION_RESOLUTIONS,
                    "verified": 0,
                    "reason_code": "official_source_does_not_expose_affiliation_metadata",
                },
            },
        }
        connection.execute(
            """
            INSERT INTO evidence_import_receipt(
                import_receipt_id,package_schema_version,input_manifest_hash,
                artifact_manifest_hash,candidate_count,ledger_entry_count,
                unlinked_entry_count,external_candidate_count,resource_count,
                validation_status,report_json,imported_at
            ) VALUES(?,?,?,?,?,?,?,?,?,'passed',?,?)
            """,
            (
                receipt_id,
                PACKAGE_SCHEMA_VERSION,
                package.input_manifest_hash,
                package.artifact_manifest_hash,
                EXPECTED_CANDIDATES,
                EXPECTED_LEDGER_ENTRIES,
                EXPECTED_UNLINKED_ENTRIES,
                EXPECTED_EXTERNAL_CANDIDATES,
                EXPECTED_RESOURCES,
                canonical_json(report),
                now,
            ),
        )

    counts = _verify_imported_state(settings, package)
    inventory = export_inventory(settings)
    candidate_inventory = export_candidate_inventory(settings)
    snapshot_hash = EvidenceRepository(settings).snapshot_hash()
    return BulkImportResult(
        receipt_id,
        True,
        counts,
        inventory,
        candidate_inventory,
        snapshot_hash,
        package.normalized_resource_manifest_hash,
    )
