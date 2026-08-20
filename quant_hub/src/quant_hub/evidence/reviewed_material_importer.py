from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from quant_hub.config import Settings
from quant_hub.platform.workflow import canonical_json

from .canonicalization import ReviewedEvidenceCanonicalizationService
from .canonicalization_builders import (
    ARXIV_ATOM_SUMMARY_NORMALIZATION,
    CROSSREF_DEPOSIT_ABSTRACT_NORMALIZATION,
    DEFAULT_CROSSREF_RECONCILIATION_DENYLIST,
    _crossref_reconciliation_allows,
    build_arxiv_reviewed_manifest,
    build_crossref_reviewed_manifest,
    method_origin_inputs_from_arxiv_readings,
    method_origin_inputs_from_reviewed_manifest,
    normalize_arxiv_atom_summary,
    reviewed_arxiv_official_abstract_excerpt,
    reviewed_crossref_official_abstract_excerpt,
)
from .contracts import FetchAttemptInput
from .database import evidence_connection
from .expansion import (
    AcquisitionCaseRecord,
    EvidenceExpansionConflict,
    EvidenceExpansionRepository,
    EvidenceExpansionService,
)
from .ids import normalize_identifier
from .providers import (
    ArxivAdapter,
    ConservativeRightsPolicy,
    CrossrefAdapter,
    ProviderAdapter,
    ProviderHttpResponse,
    ResolutionQuery,
    RightsAssessmentProposal,
    StrongIdentifierQuery,
)
from .repository import EvidenceRepository
from .resources import EvidenceResourceStore


IMPORT_POLICY_VERSION = "qrh-reviewed-material-import/v1"

ARXIV_TOTAL_DELIVERY_V4_RELATIVE_PATH = Path(
    "project_state/workers/arxiv_expansion_materials/total_delivery_manifest.json"
)
ARXIV_TOTAL_DELIVERY_V4_BYTES = 21_542
ARXIV_TOTAL_DELIVERY_V4_SHA256 = (
    "ff76c50fd2d45aa13660d2d9af0865d4abc7ae5850b2fd2488187f282d2e54bd"
)
ARXIV_INDEPENDENT_VERDICT_V4_RELATIVE_PATH = Path(
    "project_state/workers/independent_arxiv_verifier_v2/verdict_v4.json"
)
ARXIV_INDEPENDENT_VERDICT_V4_BYTES = 89_445
ARXIV_INDEPENDENT_VERDICT_V4_SHA256 = (
    "9977c3fc8ae48a8f7b3fd7c596442c33db7c005de39893b0acebdd621c2c7fc0"
)
ARXIV_INDEPENDENT_AUDIT_EVIDENCE_V4_SHA256 = (
    "595cff0ed0172042c619471d352f6f68203f3f94fc114cef864e004ac1cabb15"
)
OPEN_PDF_ARTIFACT_MANIFEST_SHA256 = (
    "0b22db44e113d0df299adb113b81cfc95bbdb9686c9329c4759e5e534ae66345"
)
OPEN_PDF_INDEPENDENT_VERIFICATION_SHA256 = (
    "801b9911885ab62988bf65cfff72007cb81104c51c76e05b9c96dea14fdfc3f3"
)
OPEN_PDF_FINAL_REVIEW_SHA256 = (
    "8d375d97ec99f16966a9384ad7c3afe0a2a3109760fa70d91da39c5b51b04d34"
)

ARXIV_RIGHTS_DECISION_CONTRACT: dict[str, tuple[str, str]] = {
    "repository_distribution_only": (
        "approved_for_managed_local_storage",
        "local_resource_with_recorded_repository_terms",
    ),
    "verified_open_license": (
        "approved_for_managed_local_storage_with_attribution",
        "local_resource_permitted_with_cc_by_attribution",
    ),
    "official_repository_access_with_embedded_no_redistribution_notice": (
        "blocked_from_managed_storage",
        "metadata_and_official_external_link_only",
    ),
    "official_repository_access_with_embedded_limited_reproduction_notice": (
        "blocked_from_managed_storage",
        "metadata_and_official_external_link_only",
    ),
    "official_repository_access_with_embedded_all_rights_reserved_notice": (
        "blocked_from_managed_storage",
        "metadata_and_official_external_link_only",
    ),
}


class ReviewedMaterialImportError(RuntimeError):
    """Reviewed artifacts are incomplete, inconsistent, or not import-eligible."""


@dataclass(frozen=True, slots=True)
class ReviewedMaterialSources:
    crossref_decisions: tuple[Path, ...]
    crossref_rights_manifest: Path
    arxiv_materials_manifest: Path
    arxiv_reading_records: Path
    reconciliation_overrides: Path | None = None
    crossref_identity_verdicts: Path | None = None
    crossref_fulltext_manifest: Path | None = None
    arxiv_total_delivery_manifest: Path | None = None
    arxiv_resolution_seed: Path | None = None
    arxiv_method_origin_inputs: Path | None = None
    arxiv_independent_verdict: Path | None = None
    open_pdf_review_summary: Path | None = None


@dataclass(frozen=True, slots=True)
class _ArxivReviewedBundle:
    material_paths: tuple[Path, ...]
    reading_paths: tuple[Path, ...]
    materials: dict[str, tuple[Path, dict[str, object]]]
    readings: dict[str, tuple[dict[str, object], dict[str, object]]]
    resolution_seed_path: Path | None
    resolution_seed: dict[str, dict[str, object]]
    method_origin_inputs_path: Path | None
    version_family_holds: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class ImportedIdentity:
    source_candidate_id: str
    paper_source_candidate_id: str
    provider: str
    identifier_scheme: str
    normalized_identifier: str
    resolution_case_id: str
    identity_decision_id: str
    resource_status: str
    resource_id: str | None = None


@dataclass(frozen=True, slots=True)
class ImportedOpenPdf:
    source_candidate_id: str
    paper_id: str
    normalized_identifier: str
    fetch_attempt_id: str
    resource_id: str
    content_sha256: str
    bytes: int
    rights_status: str


@dataclass(frozen=True, slots=True)
class ReviewedMaterialImportResult:
    crossref_identities: tuple[ImportedIdentity, ...]
    arxiv_identities: tuple[ImportedIdentity, ...]
    crossref_canonical_papers: int
    arxiv_canonical_papers: int
    method_origin_derivations: int
    open_pdf_resources: tuple[ImportedOpenPdf, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _jsonl(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ReviewedMaterialImportError(f"{path}:{number}: expected JSON object")
        rows.append(value)
    return rows


def _json_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReviewedMaterialImportError(f"{path}: expected JSON object")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _resolve_artifact(root: Path, value: object) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def _resolve_delivery_artifact(delivery_path: Path, value: object) -> Path:
    path = Path(str(value))
    if path.is_absolute():
        return path
    for root in (delivery_path.parent, *delivery_path.parents):
        candidate = root / path
        if candidate.exists():
            return candidate
    raise ReviewedMaterialImportError(
        f"{delivery_path}: referenced delivery artifact does not exist: {path}"
    )


def _verified_artifact(
    path: Path, *, expected_sha256: str, expected_bytes: int | None = None
) -> bytes:
    payload = path.read_bytes()
    actual = _sha256(payload)
    if actual != expected_sha256:
        raise ReviewedMaterialImportError(
            f"artifact hash mismatch: {path} expected {expected_sha256}, got {actual}"
        )
    if expected_bytes is not None and len(payload) != expected_bytes:
        raise ReviewedMaterialImportError(
            f"artifact byte count mismatch: {path} expected {expected_bytes}, got {len(payload)}"
        )
    return payload


def _open_pdf_review_bundle(
    summary_path: Path | None,
) -> tuple[dict[str, object] | None, dict[str, dict[str, object]]]:
    """验证开放 PDF 34 项闭集及其独立复核，不信任首轮 rights 结论。"""

    if summary_path is None:
        return None, {}
    summary_path = summary_path.resolve(strict=True)
    package_root = summary_path.parent
    if summary_path.name != "summary.json":
        raise ReviewedMaterialImportError("open PDF review entry must be summary.json")

    manifest_path = package_root / "artifact_manifest.sha256"
    manifest_payload = manifest_path.read_bytes()
    if _sha256(manifest_payload) != OPEN_PDF_ARTIFACT_MANIFEST_SHA256:
        raise ReviewedMaterialImportError(
            "open PDF artifact manifest is not the independently passed exact artifact"
        )
    manifest_rows: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        manifest_payload.decode("utf-8").splitlines(), start=1
    ):
        if not raw_line.strip():
            continue
        parts = raw_line.split("  ", 1)
        if (
            len(parts) != 2
            or len(parts[0]) != 64
            or any(char not in "0123456789abcdef" for char in parts[0])
        ):
            raise ReviewedMaterialImportError(
                f"open PDF artifact manifest line {line_number} is invalid"
            )
        relative = Path(parts[1])
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise ReviewedMaterialImportError("open PDF manifest path is not canonical")
        relative_key = relative.as_posix()
        if relative_key == manifest_path.name or relative_key in manifest_rows:
            raise ReviewedMaterialImportError("open PDF manifest path is duplicated")
        candidate = (package_root / relative).resolve(strict=True)
        if not candidate.is_relative_to(package_root) or not candidate.is_file():
            raise ReviewedMaterialImportError("open PDF manifest escapes its package")
        _verified_artifact(candidate, expected_sha256=parts[0])
        manifest_rows[relative_key] = parts[0]
    actual_files = {
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file() and path.resolve() != manifest_path
    }
    if set(manifest_rows) != actual_files:
        raise ReviewedMaterialImportError(
            "open PDF artifact manifest does not cover the exact formal file set"
        )

    def manifested_json(relative: str) -> tuple[dict[str, object], bytes]:
        expected = manifest_rows.get(relative)
        if expected is None:
            raise ReviewedMaterialImportError(
                f"open PDF manifest omits required artifact: {relative}"
            )
        payload = _verified_artifact(
            package_root / Path(relative), expected_sha256=expected
        )
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise ReviewedMaterialImportError(
                f"open PDF artifact must be a JSON object: {relative}"
            )
        return value, payload

    summary, summary_payload = manifested_json("summary.json")
    independent, independent_payload = manifested_json(
        "independent_verification.json"
    )
    if _sha256(independent_payload) != OPEN_PDF_INDEPENDENT_VERIFICATION_SHA256:
        raise ReviewedMaterialImportError(
            "open PDF independent verification is not the passed exact artifact"
        )
    if (
        summary.get("schema_version") != "qrh.evidence-open-pdf-review/v1"
        or summary.get("production_database_modified") is not False
        or summary.get("reference_modified") is not False
        or int(summary.get("reviewed_missing_papers") or -1) != 34
        or int(summary.get("allowed_pdf_count") or -1) != 4
        or int(summary.get("fail_closed_count") or -1) != 30
    ):
        raise ReviewedMaterialImportError("open PDF first-pass summary is invalid")
    if (
        independent.get("schema_version")
        != "qrh.evidence-open-pdf-independent-verification/v1"
        or independent.get("passed") is not True
        or independent.get("production_database_modified") is not False
        or independent.get("reference_modified") is not False
        or int(independent.get("reviewed_count") or -1) != 34
        or int(independent.get("allowed_count") or -1) != 4
        or int(independent.get("fail_closed_count") or -1) != 30
    ):
        raise ReviewedMaterialImportError(
            "open PDF independent verification did not pass its 34-item closed set"
        )

    final_descriptor = independent.get("final_review")
    first_descriptor = independent.get("first_pass_review")
    if not isinstance(final_descriptor, Mapping) or not isinstance(
        first_descriptor, Mapping
    ):
        raise ReviewedMaterialImportError("open PDF review descriptors are missing")
    if (
        final_descriptor.get("path") != "review_final.jsonl"
        or final_descriptor.get("sha256")
        != OPEN_PDF_FINAL_REVIEW_SHA256
        or first_descriptor.get("path") != "review.jsonl"
        or first_descriptor.get("sha256") != summary.get("review_jsonl_sha256")
    ):
        raise ReviewedMaterialImportError("open PDF final/first review binding changed")
    final_payload = _verified_artifact(
        package_root / "review_final.jsonl",
        expected_sha256=str(final_descriptor["sha256"]),
        expected_bytes=int(final_descriptor.get("bytes") or -1),
    )
    first_payload = _verified_artifact(
        package_root / "review.jsonl",
        expected_sha256=str(first_descriptor["sha256"]),
        expected_bytes=int(first_descriptor.get("bytes") or -1),
    )
    if (
        manifest_rows.get("review_final.jsonl") != _sha256(final_payload)
        or manifest_rows.get("review.jsonl") != _sha256(first_payload)
    ):
        raise ReviewedMaterialImportError("open PDF manifest/review binding disagrees")

    rows: dict[str, dict[str, object]] = {}
    for line_number, line in enumerate(
        final_payload.decode("utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ReviewedMaterialImportError(
                f"open PDF final review line {line_number} is invalid"
            )
        source_id = str(value.get("source_candidate") or "")
        if not source_id or source_id in rows:
            raise ReviewedMaterialImportError(
                "open PDF final review candidate is missing or duplicated"
            )
        rows[source_id] = value
    if len(rows) != 34:
        raise ReviewedMaterialImportError("open PDF final review is not a 34-item set")

    frozen = summary.get("frozen_input_db")
    if not isinstance(frozen, Mapping):
        raise ReviewedMaterialImportError("open PDF review omits frozen DB identity")
    relative_database = Path(str(frozen.get("path") or ""))
    workspace_root = package_root.parents[2]
    if (
        relative_database.as_posix()
        != "quant_hub/var/delivery-final-reviewed-v5-20260716-v4/db/research_papers.sqlite3"
    ):
        raise ReviewedMaterialImportError("open PDF review targets an unexpected frozen DB")
    frozen_database = (workspace_root / relative_database).resolve(strict=True)
    _verified_artifact(
        frozen_database,
        expected_sha256=str(frozen.get("sha256") or ""),
        expected_bytes=int(frozen.get("bytes") or -1),
    )
    uri = f"file:{frozen_database.as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        missing_rows = connection.execute(
            """
            SELECT paper.paper_id,catalog.title,receipt.source_candidate_id
            FROM paper
            JOIN paper_catalog_projection AS catalog USING(paper_id)
            JOIN evidence_canonicalization_receipt AS receipt USING(paper_id)
            WHERE NOT EXISTS(
                SELECT 1 FROM paper_resource AS resource
                WHERE resource.paper_id=paper.paper_id
                  AND resource.verification_status='verified'
            ) AND NOT EXISTS(
                SELECT 1
                FROM evidence_canonical_resource_attachment AS attachment
                JOIN paper_resource AS resource USING(resource_id)
                WHERE attachment.paper_id=paper.paper_id
                  AND resource.verification_status='verified'
            )
            ORDER BY receipt.source_candidate_id COLLATE BINARY
            """
        ).fetchall()
        db_inventory: dict[str, dict[str, object]] = {}
        for db_row in missing_rows:
            paper_id = str(db_row["paper_id"])
            identifiers = {
                (str(identifier["scheme"]).casefold(), str(identifier["normalized_value"]))
                for identifier in connection.execute(
                    "SELECT scheme,normalized_value FROM identifier_assignment_projection "
                    "WHERE paper_id=?",
                    (paper_id,),
                )
            }
            db_inventory[str(db_row["source_candidate_id"])] = {
                "paper_id": paper_id,
                "title": str(db_row["title"]),
                "identifiers": identifiers,
            }
    _verified_artifact(
        frozen_database,
        expected_sha256=str(frozen.get("sha256") or ""),
        expected_bytes=int(frozen.get("bytes") or -1),
    )
    if len(db_inventory) != 34 or set(db_inventory) != set(rows):
        raise ReviewedMaterialImportError(
            "open PDF final review does not equal the frozen DB missing-resource set"
        )

    allowed_results = independent.get("allowed_results")
    if not isinstance(allowed_results, list):
        raise ReviewedMaterialImportError("open PDF independent allowed set is missing")
    independent_allowed: dict[str, Mapping[str, object]] = {}
    for result in allowed_results:
        if not isinstance(result, Mapping):
            raise ReviewedMaterialImportError("open PDF independent result is malformed")
        source_id = str(result.get("candidate_id") or "")
        checks = result.get("checks")
        if (
            not source_id
            or source_id in independent_allowed
            or result.get("passed") is not True
            or not isinstance(checks, Mapping)
            or not checks
            or any(value is not True for value in checks.values())
        ):
            raise ReviewedMaterialImportError(
                "open PDF independent allowed result did not pass every check"
            )
        independent_allowed[source_id] = result
    frozen_allowed = independent.get("frozen_allowed_candidates")
    if (
        not isinstance(frozen_allowed, list)
        or sorted(str(value) for value in frozen_allowed)
        != sorted(independent_allowed)
        or sorted(str(value) for value in summary.get("allowed_candidates", []))
        != sorted(independent_allowed)
    ):
        raise ReviewedMaterialImportError("open PDF allowed candidate sets disagree")

    allowed_projection: list[dict[str, object]] = []
    for source_id, row in sorted(rows.items()):
        db_row = db_inventory[source_id]
        identifier = row.get("identifier")
        if not isinstance(identifier, Mapping):
            raise ReviewedMaterialImportError(f"{source_id}: identifier is missing")
        scheme = str(identifier.get("scheme") or "").casefold()
        normalized = normalize_identifier(scheme, str(identifier.get("value") or ""))
        if (
            str(row.get("paper_id") or "") != db_row["paper_id"]
            or str(row.get("title") or "") != db_row["title"]
            or (scheme, normalized) not in db_row["identifiers"]
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: review identity differs from the frozen DB"
            )
        independent_result = independent_allowed.get(source_id)
        if independent_result is None:
            failed_validation = row.get("pdf_validation")
            transport = row.get("get")
            if (
                row.get("decision") != "fail_closed"
                or not str(row.get("failure_reason") or "").strip()
                or row.get("local_pdf") is not None
                or not isinstance(transport, Mapping)
                or (
                    transport.get("performed") is True
                    and isinstance(failed_validation, Mapping)
                    and failed_validation.get("magic_pdf") is True
                    and failed_validation.get("pdf_opened") is True
                    and failed_validation.get("title_match") is True
                    and failed_validation.get("identifier_match") is True
                )
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: non-allowed item did not fail closed"
                )
            continue
        pdf = independent_result.get("pdf")
        rights = independent_result.get("rights")
        local_pdf = row.get("local_pdf")
        transport = row.get("get")
        validation = row.get("pdf_validation")
        row_rights = row.get("rights")
        if not all(
            isinstance(value, Mapping)
            for value in (pdf, rights, local_pdf, transport, validation, row_rights)
        ):
            raise ReviewedMaterialImportError(f"{source_id}: allowed item is malformed")
        assert isinstance(pdf, Mapping)
        assert isinstance(rights, Mapping)
        assert isinstance(local_pdf, Mapping)
        assert isinstance(transport, Mapping)
        assert isinstance(validation, Mapping)
        assert isinstance(row_rights, Mapping)
        if (
            row.get("decision") != "allow_import_verified_open_pdf"
            or str(independent_result.get("paper_id") or "") != db_row["paper_id"]
            or normalize_identifier("doi", str(independent_result.get("doi") or ""))
            != normalized
            or str(independent_result.get("title") or "") != db_row["title"]
            or local_pdf.get("path") != pdf.get("path")
            or local_pdf.get("sha256") != pdf.get("sha256")
            or int(local_pdf.get("bytes") or -1) != int(pdf.get("bytes") or -2)
            or transport.get("performed") is not True
            or int(transport.get("http_status") or 0) != 200
            or transport.get("sha256") != pdf.get("sha256")
            or int(transport.get("bytes") or -1) != int(pdf.get("bytes") or -2)
            or validation.get("magic_pdf") is not True
            or validation.get("pdf_opened") is not True
            or validation.get("title_match") is not True
            or validation.get("identifier_match") is not True
            or int(validation.get("page_count") or 0) <= 0
            or row_rights.get("license") != rights.get("license")
            or row_rights.get("license_url") != rights.get("license_url")
            or row_rights.get("rights_evidence_url") != rights.get("evidence_url")
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: final review and independent verification disagree"
            )
        pdf_path = (package_root / Path(str(pdf.get("path") or ""))).resolve(strict=True)
        if not pdf_path.is_relative_to(package_root):
            raise ReviewedMaterialImportError(f"{source_id}: PDF path escapes package")
        pdf_payload = _verified_artifact(
            pdf_path,
            expected_sha256=str(pdf.get("sha256") or ""),
            expected_bytes=int(pdf.get("bytes") or -1),
        )
        if not pdf_payload.startswith(b"%PDF-"):
            raise ReviewedMaterialImportError(f"{source_id}: allowed PDF magic is invalid")
        evidence_artifact = rights.get("evidence_artifact")
        if not isinstance(evidence_artifact, Mapping):
            raise ReviewedMaterialImportError(f"{source_id}: rights artifact is missing")
        rights_path = (
            package_root / Path(str(evidence_artifact.get("path") or ""))
        ).resolve(strict=True)
        if not rights_path.is_relative_to(package_root):
            raise ReviewedMaterialImportError(f"{source_id}: rights path escapes package")
        _verified_artifact(
            rights_path,
            expected_sha256=str(evidence_artifact.get("sha256") or ""),
            expected_bytes=int(evidence_artifact.get("bytes") or -1),
        )
        allowed_projection.append(
            {
                "source_candidate_id": source_id,
                "paper_id": str(db_row["paper_id"]),
                "identifier_scheme": scheme,
                "normalized_identifier": normalized,
                "title": str(db_row["title"]),
                "source_url": str(row.get("source_url") or ""),
                "final_url": str(transport.get("final_url") or ""),
                "content_sha256": str(pdf["sha256"]),
                "bytes": int(pdf["bytes"]),
                "relative_path": str(pdf["path"]),
                "license": str(rights.get("license") or ""),
                "license_url": str(rights.get("license_url") or ""),
                "rights_evidence_url": str(rights.get("evidence_url") or ""),
                "rights_evidence_sha256": str(evidence_artifact.get("sha256") or ""),
                "rights_evidence_path": str(evidence_artifact.get("path") or ""),
            }
        )
    if len(allowed_projection) != 4:
        raise ReviewedMaterialImportError("open PDF allowed projection must contain four rows")
    if int(summary.get("pdf_bytes") or -1) != sum(
        int(row["bytes"]) for row in allowed_projection
    ):
        raise ReviewedMaterialImportError("open PDF summary byte total changed")
    return (
        {
            "schema_version": "qrh-reviewed-open-pdf-import/v1",
            "manifest": {
                "path": "project_state/workers/evidence_open_pdf_review_20260716/artifact_manifest.sha256",
                "bytes": len(manifest_payload),
                "sha256": _sha256(manifest_payload),
                "covered_files": len(manifest_rows),
            },
            "summary_sha256": _sha256(summary_payload),
            "independent_verification_sha256": _sha256(independent_payload),
            "final_review_sha256": _sha256(final_payload),
            "reviewed_count": len(rows),
            "allowed_count": len(allowed_projection),
            "fail_closed_count": len(rows) - len(allowed_projection),
            "allowed_projection": allowed_projection,
            "allowed_projection_sha256": _sha256(
                canonical_json(allowed_projection).encode("utf-8")
            ),
            "frozen_input_database": {
                "path": relative_database.as_posix(),
                "bytes": int(frozen["bytes"]),
                "sha256": str(frozen["sha256"]),
            },
        },
        rows,
    )


def _reconciliation_overrides(
    path: Path | None,
) -> dict[str, Mapping[str, str]]:
    if path is None:
        return {}
    payload = _json_object(path)
    rows = payload.get("decisions", payload)
    if not isinstance(rows, Mapping):
        raise ReviewedMaterialImportError(
            "reconciliation override must be an object or contain a decisions object"
        )
    output: dict[str, Mapping[str, str]] = {}
    for source_id, value in rows.items():
        if not isinstance(value, Mapping):
            raise ReviewedMaterialImportError(
                f"{source_id}: reconciliation decision must be an object"
            )
        output[str(source_id)] = {str(key): str(item) for key, item in value.items()}
    return output


def _crossref_identity_verdict_rows(
    path: Path | None,
    *,
    decision_rows: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    if path is None:
        return {}
    output: dict[str, dict[str, object]] = {}
    required_official_checks = {
        "complete_author_sequence_exact",
        "doi_exact",
        "envelope_status_ok",
        "meta_http_200",
        "meta_sha_matches_cache_manifest",
        "publication_year_exact",
        "raw_bytes_match_meta",
        "raw_sha_matches_cache_manifest",
        "raw_sha_matches_decision",
        "raw_sha_matches_meta",
        "title_exact",
        "venue_exact_or_alias",
    }
    required_local_checks = {
        "all_author_families_present",
        "decision_and_ledger_raw_label_equal",
        "decision_and_ledger_title_equal",
        "decision_and_ledger_year_equal",
        "source_exists",
        "title_present",
        "venue_present_when_expected",
        "year_present",
    }
    for row in _jsonl(path):
        if row.get("schema_version") != "qrh.independent-crossref-identity-verdict/v1":
            raise ReviewedMaterialImportError(
                f"{path}: unsupported independent identity verdict schema"
            )
        source_id = str(row.get("candidate_id") or "")
        if not source_id or source_id in output:
            raise ReviewedMaterialImportError(
                f"{path}: invalid or duplicate identity verdict for {source_id!r}"
            )
        decision = decision_rows.get(source_id)
        if decision is None:
            raise ReviewedMaterialImportError(
                f"{source_id}: identity verdict has no frozen Crossref decision"
            )
        if normalize_identifier("doi", str(row.get("selected_doi") or "")) != normalize_identifier(
            "doi", str(decision.get("selected_doi") or "")
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: identity verdict DOI does not match frozen decision"
            )
        tier = row.get("tier_review")
        if not isinstance(tier, Mapping) or str(tier.get("as_produced") or "") != str(
            decision.get("identity_match_tier") or ""
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: identity verdict tier is not bound to frozen decision"
            )
        official_checks = row.get("official_checks")
        local_checks = row.get("local_checks")
        official_evidence = row.get("official_exact_doi_evidence")
        rights_review = row.get("rights_review")
        version_review = row.get("version_review")
        verification = decision.get("direct_doi_verification")
        raw_body = (
            verification.get("raw_body_evidence")
            if isinstance(verification, Mapping)
            else None
        )
        if (
            row.get("database_write_performed") is not False
            or not isinstance(official_checks, Mapping)
            or set(official_checks) != required_official_checks
            or any(official_checks[key] is not True for key in required_official_checks)
            or not isinstance(local_checks, Mapping)
            or set(local_checks) != required_local_checks
            or any(local_checks[key] is not True for key in required_local_checks)
            or not isinstance(official_evidence, Mapping)
            or not isinstance(rights_review, Mapping)
            or rights_review.get("verdict") != "PASS"
            or not isinstance(version_review, Mapping)
            or not isinstance(raw_body, Mapping)
            or official_evidence.get("recomputed_sha256")
            != verification.get("response_sha256")
            or official_evidence.get("recomputed_sha256") != raw_body.get("sha256")
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: independent identity verdict is not bound to all exact evidence"
            )
        official_body_path = Path(str(official_evidence.get("body_path") or "")).as_posix()
        official_meta_path = Path(str(official_evidence.get("meta_path") or "")).as_posix()
        decision_body_path = Path(str(raw_body.get("body_path") or "")).as_posix()
        decision_meta_path = Path(str(raw_body.get("meta_path") or "")).as_posix()
        if (
            not official_body_path
            or not official_meta_path
            or not decision_body_path.endswith(official_body_path)
            or not decision_meta_path.endswith(official_meta_path)
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: independent identity evidence paths differ from frozen bytes"
            )
        if row.get("identity_verdict") == "PASS" and version_review.get("verdict") != "PASS":
            raise ReviewedMaterialImportError(
                f"{source_id}: PASS identity lacks a PASS version review"
            )
        tier_changed = tier.get("as_produced") != tier.get("required")
        if row.get("identity_verdict") == "PASS" and (
            (
                not tier_changed
                and (
                    row.get("consumption_verdict_as_produced") != "PASS"
                    or tier.get("verdict") != "PASS"
                )
            )
            or (
                tier_changed
                and (
                    row.get("consumption_verdict_as_produced") != "FAIL"
                    or tier.get("verdict") != "FAIL"
                )
            )
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: identity/tier/consumption verdicts are contradictory"
            )
        output[source_id] = row
    missing = sorted(set(decision_rows) - set(output))
    if missing:
        raise ReviewedMaterialImportError(
            f"independent identity verdicts do not cover frozen decisions: {missing}"
        )
    safe = sorted(
        source_id
        for source_id, row in output.items()
        if row.get("identity_verdict") == "PASS"
    )
    if len(safe) != 31 or output.get("P095", {}).get("identity_verdict") != "FAIL":
        raise ReviewedMaterialImportError(
            "independent identity verdict closed set must be 31 PASS plus P095 FAIL"
        )
    reconciled = {
        source_id
        for source_id, row in output.items()
        if row.get("identity_verdict") == "PASS"
        and isinstance(row.get("tier_review"), Mapping)
        and row["tier_review"].get("as_produced")
        != row["tier_review"].get("required")
    }
    if reconciled != {"P107", "P126", "P183", "U038", "U054", "U055"}:
        raise ReviewedMaterialImportError(
            "independent identity tier reconciliation closed set changed"
        )
    p095 = output["P095"]
    if (
        p095.get("consumption_verdict_as_produced") != "FAIL"
        or not isinstance(p095.get("tier_review"), Mapping)
        or p095["tier_review"].get("verdict") != "FAIL"
        or not isinstance(p095.get("version_review"), Mapping)
        or p095["version_review"].get("verdict") != "FAIL"
    ):
        raise ReviewedMaterialImportError("P095 version-family denial changed")
    return output


def _crossref_rows(paths: tuple[Path, ...]) -> dict[str, dict[str, object]]:
    output: dict[str, dict[str, object]] = {}
    for path in paths:
        for row in _jsonl(path):
            source_id = str(row.get("candidate_id") or "")
            if not source_id:
                raise ReviewedMaterialImportError(f"{path}: missing candidate_id")
            prior = output.get(source_id)
            if prior is not None and prior != row:
                raise ReviewedMaterialImportError(
                    f"conflicting reviewed Crossref decisions for {source_id}"
                )
            output[source_id] = row
    return output


def _crossref_body(row: Mapping[str, object]) -> tuple[bytes, dict[str, object]]:
    verification = row.get("direct_doi_verification")
    if not isinstance(verification, Mapping):
        raise ReviewedMaterialImportError("accepted Crossref row lacks direct verification")
    evidence = verification.get("raw_body_evidence")
    if not isinstance(evidence, Mapping):
        raise ReviewedMaterialImportError("accepted Crossref row lacks raw body evidence")
    body_path = Path(str(evidence.get("body_path") or ""))
    meta_path = Path(str(evidence.get("meta_path") or ""))
    expected_hash = str(evidence.get("sha256") or "")
    if len(expected_hash) != 64 or not body_path.is_absolute() or not meta_path.is_absolute():
        raise ReviewedMaterialImportError(
            "Crossref exact-body evidence requires absolute paths and a SHA-256"
        )
    payload = _verified_artifact(
        body_path,
        expected_sha256=expected_hash,
        expected_bytes=int(evidence["bytes"]),
    )
    metadata = _json_object(meta_path)
    if (
        verification.get("response_sha256") != expected_hash
        or metadata.get("sha256") != expected_hash
        or int(metadata.get("bytes") or -1) != len(payload)
        or int(metadata.get("http_status") or 0) != int(verification.get("http_status") or 0)
        or metadata.get("endpoint") != verification.get("endpoint")
    ):
        raise ReviewedMaterialImportError("Crossref body/meta/decision receipt mismatch")
    return payload, metadata


def _crossref_rights_rows(
    path: Path,
    *,
    decision_rows: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    output: dict[str, dict[str, object]] = {}
    for row in _jsonl(path):
        if row.get("schema_version") != "qrh.crossref-identity-review/v1":
            raise ReviewedMaterialImportError(
                f"{path}: unsupported Crossref rights row schema"
            )
        source_id = str(row.get("candidate_id") or "")
        if not source_id or source_id in output:
            raise ReviewedMaterialImportError(
                f"{path}: invalid or duplicate Crossref rights row for {source_id!r}"
            )
        if source_id not in decision_rows:
            raise ReviewedMaterialImportError(
                f"{path}: unknown Crossref rights row for {source_id}"
            )
        output[source_id] = row
    if set(output) != set(decision_rows):
        missing = sorted(set(decision_rows) - set(output))
        raise ReviewedMaterialImportError(
            f"Crossref rights rows do not cover the frozen decision set: {missing}"
        )
    return output


def _validate_crossref_rights_row(
    decision_row: Mapping[str, object],
    rights_row: Mapping[str, object] | None,
    identity_verdict: Mapping[str, object] | None = None,
) -> None:
    source_id = str(decision_row.get("candidate_id") or "")
    if rights_row is None:
        raise ReviewedMaterialImportError(
            f"{source_id}: accepted identity has no reviewed rights/resource disposition"
        )
    verification = decision_row.get("direct_doi_verification") or {}
    if not isinstance(verification, Mapping):
        raise ReviewedMaterialImportError(f"{source_id}: malformed direct DOI verification")
    doi = normalize_identifier("doi", str(decision_row.get("selected_doi") or ""))
    if (
        normalize_identifier("doi", str(rights_row.get("doi") or "")) != doi
        or rights_row.get("exact_response_sha256") != verification.get("response_sha256")
        or rights_row.get("exact_doi_endpoint") != verification.get("endpoint")
    ):
        raise ReviewedMaterialImportError(
            f"{source_id}: identity and rights manifests are not bound to the same exact response"
        )
    licenses = rights_row.get("licenses")
    offers = rights_row.get("official_fulltext_offers")
    if not isinstance(licenses, list) or not isinstance(offers, list):
        raise ReviewedMaterialImportError(
            f"{source_id}: Crossref rights row has malformed license/offer arrays"
        )
    license_classes = sorted(
        {
            str(license_row.get("class") or "")
            for license_row in licenses
            if isinstance(license_row, Mapping)
        }
    )
    if any(not isinstance(row, Mapping) for row in licenses + offers):
        raise ReviewedMaterialImportError(
            f"{source_id}: Crossref rights license/offer row is malformed"
        )
    verified_offers: list[Mapping[str, object]] = []
    head_probe_count = 0
    for offer in offers:
        assert isinstance(offer, Mapping)
        probe = offer.get("mime_probe")
        if isinstance(probe, Mapping):
            head_probe_count += 1
        is_available = offer.get("acquisition_status") == "available_verified_open_pdf"
        if not is_available:
            if offer.get("mime_verified_pdf") is True:
                raise ReviewedMaterialImportError(
                    f"{source_id}: non-available Crossref offer claims a verified PDF"
                )
            continue
        applicable = offer.get("applicable_open_licenses")
        if (
            offer.get("mime_verified_pdf") is not True
            or offer.get("declared_content_type") != "application/pdf"
            or not str(offer.get("url") or "").startswith("https://")
            or not isinstance(probe, Mapping)
            or probe.get("request_method") != "HEAD"
            or int(probe.get("http_status") or 0) != 200
            or probe.get("content_type") != "application/pdf"
            or not isinstance(applicable, list)
            or not applicable
            or any(
                not isinstance(license_row, Mapping)
                or license_row.get("class") != "cc_by"
                for license_row in applicable
            )
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: available Crossref PDF lacks separate license and HEAD evidence"
            )
        verified_offers.append(offer)
    expected_best = "available_verified_open_pdf" if verified_offers else "metadata_only"
    if (
        int(rights_row.get("verified_open_pdf_offer_count") or 0)
        != len(verified_offers)
        or rights_row.get("best_acquisition_status") != expected_best
    ):
        raise ReviewedMaterialImportError(
            f"{source_id}: Crossref best acquisition status is not derived from verified offers"
        )
    if identity_verdict is None:
        return
    independent = identity_verdict.get("rights_review")
    if not isinstance(independent, Mapping):
        raise ReviewedMaterialImportError(
            f"{source_id}: independent identity verdict has no rights review"
        )
    if (
        independent.get("verdict") != "PASS"
        or independent.get("best_acquisition_status") != expected_best
        or independent.get("rights_status") != rights_row.get("rights_status")
        or sorted(str(value) for value in (independent.get("license_classes") or []))
        != license_classes
        or int(independent.get("head_probe_count") or 0) != head_probe_count
        or independent.get("false_acquisition_claims") != []
        or independent.get("body_acquired_by_this_review") is not False
        or independent.get("available_offer_has_separate_cc_and_head_evidence")
        is not True
        or independent.get("head_is_availability_and_mime_evidence_only") is not True
        or independent.get("tdm_or_publisher_terms_never_treated_as_open") is not True
    ):
        raise ReviewedMaterialImportError(
            f"{source_id}: Crossref rights row contradicts the independent verdict"
        )


def _crossref_fulltext_rows(
    path: Path | None,
    *,
    decision_rows: Mapping[str, Mapping[str, object]],
    rights_rows: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    if path is None:
        return {}
    payload = _json_object(path)
    if payload.get("schema_version") != "qrh-crossref-open-pdf-acquisition/v1":
        raise ReviewedMaterialImportError(
            f"{path}: unsupported Crossref fulltext acquisition schema"
        )
    rows = payload.get("items")
    if not isinstance(rows, list):
        raise ReviewedMaterialImportError(f"{path}: fulltext manifest has no items array")
    output: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ReviewedMaterialImportError("Crossref fulltext item must be an object")
        source_id = str(row.get("candidate_id") or "")
        if not source_id or source_id in output:
            raise ReviewedMaterialImportError(
                f"invalid or duplicate Crossref fulltext candidate: {source_id!r}"
            )
        decision = decision_rows.get(source_id)
        rights_row = rights_rows.get(source_id)
        if decision is None or rights_row is None:
            raise ReviewedMaterialImportError(
                f"{source_id}: fulltext item has no reviewed identity/rights source"
            )
        doi = normalize_identifier("doi", str(row.get("doi") or ""))
        if doi != normalize_identifier("doi", str(decision.get("selected_doi") or "")):
            raise ReviewedMaterialImportError(
                f"{source_id}: fulltext DOI differs from frozen identity decision"
            )
        binding = row.get("identity_binding")
        verification = decision.get("direct_doi_verification")
        if not isinstance(binding, Mapping) or not isinstance(verification, Mapping):
            raise ReviewedMaterialImportError(f"{source_id}: fulltext identity binding malformed")
        if (
            binding.get("exact_doi_endpoint") != verification.get("endpoint")
            or binding.get("exact_response_sha256") != verification.get("response_sha256")
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: fulltext is not bound to the exact reviewed DOI response"
            )
        request = row.get("request")
        validation = row.get("pdf_validation")
        rights = row.get("rights")
        reading = row.get("reading")
        if not all(isinstance(value, Mapping) for value in (request, validation, rights, reading)):
            raise ReviewedMaterialImportError(
                f"{source_id}: fulltext request/validation/rights/reading malformed"
            )
        assert isinstance(request, Mapping)
        assert isinstance(validation, Mapping)
        assert isinstance(rights, Mapping)
        assert isinstance(reading, Mapping)
        body_path = _resolve_artifact(path.parent, request.get("body_path"))
        body = _verified_artifact(
            body_path,
            expected_sha256=str(request.get("sha256") or ""),
            expected_bytes=int(request.get("bytes") or -1),
        )
        receipt_path = _resolve_artifact(path.parent, request.get("request_receipt_path"))
        _verified_artifact(
            receipt_path,
            expected_sha256=str(request.get("request_receipt_sha256") or ""),
        )
        page_text_path = _resolve_artifact(path.parent, validation.get("page_text_path"))
        page_payload = _verified_artifact(
            page_text_path,
            expected_sha256=str(validation.get("page_text_file_sha256") or ""),
        )
        page_rows = [
            json.loads(line)
            for line in page_payload.decode("utf-8").splitlines()
            if line.strip()
        ]
        projected_page_rows = [
            {
                "page": page_row.get("page"),
                "text_bytes": page_row.get("text_bytes"),
                "text_sha256": page_row.get("text_sha256"),
            }
            for page_row in page_rows
        ]
        if projected_page_rows != validation.get("page_text") or any(
            not isinstance(page_row.get("text"), str)
            or len(str(page_row.get("text")).encode("utf-8"))
            != int(page_row.get("text_bytes") or -1)
            or _sha256(str(page_row.get("text")).encode("utf-8"))
            != page_row.get("text_sha256")
            for page_row in page_rows
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: page-text file differs from fulltext manifest"
            )
        fulltext_path = _resolve_artifact(path.parent, validation.get("fulltext_path"))
        _verified_artifact(
            fulltext_path,
            expected_sha256=str(validation.get("fulltext_sha256") or ""),
        )
        mime = str(request.get("content_type") or "").split(";", 1)[0].strip().casefold()
        if (
            request.get("successful") is not True
            or str(request.get("method") or "").upper() != "GET"
            or int(request.get("http_status") or 0) != 200
            or mime != "application/pdf"
            or validation.get("magic_ok") is not True
            or validation.get("eof_ok") is not True
            or not body.startswith(b"%PDF-")
            or b"%%EOF" not in body[-2048:]
            or int(validation.get("pages") or 0) != len(page_rows)
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: downloaded fulltext failed transport/PDF validation"
            )
        approved_offers = [
            offer
            for offer in rights_row.get("official_fulltext_offers", []) or []
            if isinstance(offer, Mapping)
            and offer.get("acquisition_status") == "available_verified_open_pdf"
        ]
        if len(approved_offers) != 1 or str(request.get("request_url") or "") != str(
            approved_offers[0].get("url") or ""
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: GET is not bound to the reviewed exact-version offer"
            )
        if rights.get("license_evidence_sha256") != verification.get("response_sha256"):
            raise ReviewedMaterialImportError(
                f"{source_id}: post-GET rights review is not bound to exact DOI evidence"
            )
        if (
            row.get("eligible_for_canonical_resource") is not False
            or row.get("eligible_for_production_ingest") is not False
            or rights.get("redistribution_authorized") is not False
            or row.get("status") != "failed_closed"
            or reading.get("core_conclusions") not in ([], ())
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: current rights-conflicted fulltext must remain failed closed"
            )
        output[source_id] = row
    return output


def _material_items(path: Path) -> tuple[Path, dict[str, dict[str, object]]]:
    payload = _json_object(path)
    items = payload.get("items")
    if not isinstance(items, list):
        raise ReviewedMaterialImportError("arXiv materials manifest has no items array")
    output: dict[str, dict[str, object]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ReviewedMaterialImportError("arXiv material item must be an object")
        source_id = str(item.get("source_candidate_id") or "")
        if not source_id or source_id in output:
            raise ReviewedMaterialImportError(
                f"invalid or duplicate arXiv source candidate: {source_id!r}"
            )
        output[source_id] = item
    return path.parent, output


def _select_delivery_entry(
    entries: list[dict[str, object]],
    *,
    schema_version: str,
    name: str | None = None,
) -> dict[str, object]:
    matching = [
        entry
        for entry in entries
        if entry.get("schema_version") == schema_version
        and (name is None or Path(str(entry.get("path") or "")).name == name)
    ]
    if len(matching) != 1:
        raise ReviewedMaterialImportError(
            f"total delivery expected one {schema_version} {name or ''}, found {len(matching)}"
        )
    return matching[0]


def _validate_arxiv_independent_gate(
    verdict_path: Path | None,
    *,
    delivery_path: Path | None,
) -> None:
    if delivery_path is None:
        if verdict_path is None:
            return
        raise ReviewedMaterialImportError(
            "an arXiv independent verdict requires the total delivery manifest"
        )
    if verdict_path is None:
        raise ReviewedMaterialImportError(
            "the arXiv total delivery requires the exact independent V4 verdict"
        )

    resolved_delivery = delivery_path.resolve(strict=True)
    workspace_root = resolved_delivery.parents[3]
    expected_delivery = (
        workspace_root / ARXIV_TOTAL_DELIVERY_V4_RELATIVE_PATH
    ).resolve(strict=True)
    if resolved_delivery != expected_delivery:
        raise ReviewedMaterialImportError(
            "arXiv total delivery is not the frozen V4 subject path"
        )
    delivery_bytes = _verified_artifact(
        resolved_delivery,
        expected_sha256=ARXIV_TOTAL_DELIVERY_V4_SHA256,
        expected_bytes=ARXIV_TOTAL_DELIVERY_V4_BYTES,
    )

    resolved_verdict = verdict_path.resolve(strict=True)
    expected_verdict = (
        workspace_root / ARXIV_INDEPENDENT_VERDICT_V4_RELATIVE_PATH
    ).resolve(strict=True)
    if resolved_verdict != expected_verdict:
        raise ReviewedMaterialImportError(
            "independent arXiv verdict is not the frozen V4 verdict path"
        )
    verdict_bytes = _verified_artifact(
        resolved_verdict,
        expected_sha256=ARXIV_INDEPENDENT_VERDICT_V4_SHA256,
        expected_bytes=ARXIV_INDEPENDENT_VERDICT_V4_BYTES,
    )
    verdict = json.loads(verdict_bytes.decode("utf-8"))
    if not isinstance(verdict, dict):
        raise ReviewedMaterialImportError("independent arXiv V4 verdict must be an object")
    if verdict.get("schema_version") != "qrh-independent-arxiv-verdict/v4":
        raise ReviewedMaterialImportError(
            f"{verdict_path}: only the exact independent arXiv V4 verdict is supported"
        )

    def verify_workspace_descriptor(
        descriptor: object,
        *,
        label: str,
        expected_relative: Path | None = None,
        expected_schema: str | None = None,
    ) -> Path:
        if not isinstance(descriptor, Mapping):
            raise ReviewedMaterialImportError(f"{label}: descriptor must be an object")
        relative = Path(str(descriptor.get("path") or ""))
        if relative.is_absolute() or not relative.parts:
            raise ReviewedMaterialImportError(f"{label}: descriptor path must be workspace-relative")
        if expected_relative is not None and relative.as_posix() != expected_relative.as_posix():
            raise ReviewedMaterialImportError(f"{label}: descriptor path differs from V4 contract")
        candidate = (workspace_root / relative).resolve(strict=True)
        if not candidate.is_relative_to(workspace_root):
            raise ReviewedMaterialImportError(f"{label}: descriptor escapes the workspace")
        if expected_schema is not None and descriptor.get("schema_version") != expected_schema:
            raise ReviewedMaterialImportError(f"{label}: descriptor schema differs from V4 contract")
        _verified_artifact(
            candidate,
            expected_sha256=str(descriptor.get("sha256") or ""),
            expected_bytes=int(descriptor.get("bytes") or -1),
        )
        return candidate

    subject = verdict.get("subject")
    if not isinstance(subject, Mapping):
        raise ReviewedMaterialImportError("independent arXiv verdict has no subject binding")
    if (
        subject.get("path") != ARXIV_TOTAL_DELIVERY_V4_RELATIVE_PATH.as_posix()
        or subject.get("schema_version") != "qrh-arxiv-expansion-delivery/v1"
        or int(subject.get("bytes") or -1) != ARXIV_TOTAL_DELIVERY_V4_BYTES
        or subject.get("sha256") != ARXIV_TOTAL_DELIVERY_V4_SHA256
        or len(delivery_bytes) != ARXIV_TOTAL_DELIVERY_V4_BYTES
        or _sha256(delivery_bytes) != ARXIV_TOTAL_DELIVERY_V4_SHA256
    ):
        raise ReviewedMaterialImportError(
            "independent arXiv V4 verdict is not bound to the exact frozen subject"
        )

    counts = verdict.get("recomputed_counts")
    descriptor_verification = verdict.get("descriptor_verification")
    search_binding = verdict.get("search_one_way_binding")
    semantic_sets = verdict.get("semantic_sets")
    source_integrity = verdict.get("source_integrity")
    defects = verdict.get("defects")
    if not all(
        isinstance(value, Mapping)
        for value in (
            counts,
            descriptor_verification,
            search_binding,
            semantic_sets,
            source_integrity,
        )
    ) or not isinstance(defects, list):
        raise ReviewedMaterialImportError("independent arXiv V4 verdict is malformed")
    assert isinstance(counts, Mapping)
    assert isinstance(descriptor_verification, Mapping)
    assert isinstance(search_binding, Mapping)
    assert isinstance(semantic_sets, Mapping)
    assert isinstance(source_integrity, Mapping)

    expected_counts = {
        "checks_total": 673,
        "checks_passed": 673,
        "top_level_descriptors": 43,
        "top_level_descriptors_verified": 43,
        "search_inventory_files": 193,
        "search_inventory_files_verified": 193,
        "identity_review_inventory_files": 8,
        "identity_review_inventory_files_verified": 8,
        "official_material_packages": 29,
        "formal_citation_packages": 22,
        "associated_method_origin_packages": 7,
        "new_identity_items": 18,
        "new_identity_pass": 18,
        "version_family_holds": 4,
        "version_family_holds_unmerged": 4,
        "resolution_seed_rows": 29,
        "material_inventory_files": 222,
        "material_inventory_files_verified": 222,
        "pdf_files_verified": 29,
        "pdf_pages_verified": 669,
        "official_raw_responses_verified": 29,
        "reading_records": 29,
        "reading_evidence_locators": 135,
        "reading_evidence_hash_anchored": 135,
        "reading_evidence_missing_page_hash": 0,
        "targeted_semantic_spot_checks": 4,
    }
    if any(int(counts.get(key) or 0) != value for key, value in expected_counts.items()):
        raise ReviewedMaterialImportError("independent arXiv V4 recomputed counts changed")

    category_counts = descriptor_verification.get("category_counts")
    if (
        descriptor_verification.get("verdict") != "PASS"
        or descriptor_verification.get(
            "all_declared_path_bytes_sha256_and_schema_recomputed"
        )
        is not True
        or not isinstance(category_counts, Mapping)
        or sum(int(value) for value in category_counts.values()) != 43
    ):
        raise ReviewedMaterialImportError("independent arXiv V4 descriptor audit failed")

    audit_descriptor = search_binding.get("audit")
    validation_descriptor = search_binding.get("validation")
    if (
        search_binding.get("verdict") != "PASS"
        or search_binding.get("audit_inventory_total") != 193
        or search_binding.get("reverse_validation_entry_present") is not False
        or search_binding.get("reverse_validation_entries") != []
        or search_binding.get("validation_declared_audit_sha256")
        != "52cc76e7e9316c608c4600ff13a264c097ef055b23b49e6e8c871371e8f7d894"
        or not isinstance(audit_descriptor, Mapping)
        or audit_descriptor.get("bytes") != 826_964
        or audit_descriptor.get("sha256")
        != "52cc76e7e9316c608c4600ff13a264c097ef055b23b49e6e8c871371e8f7d894"
        or not isinstance(validation_descriptor, Mapping)
        or validation_descriptor.get("bytes") != 550
        or validation_descriptor.get("sha256")
        != "0393f38da8779e58af425674962565f9b16bc05a30f46484adaf0c58252b2ecb"
    ):
        raise ReviewedMaterialImportError("independent arXiv V4 one-way search binding failed")
    verify_workspace_descriptor(
        audit_descriptor,
        label="V4 search audit",
        expected_relative=Path(
            "project_state/workers/arxiv_expansion_materials/"
            "bounded_title_search/arxiv_title_search_audit.json"
        ),
    )
    verify_workspace_descriptor(
        validation_descriptor,
        label="V4 search validation",
        expected_relative=Path(
            "project_state/workers/arxiv_expansion_materials/"
            "bounded_title_search/validation_report.json"
        ),
    )

    import_sequence = verdict.get("import_sequence")
    if not isinstance(import_sequence, list) or len(import_sequence) != 2:
        raise ReviewedMaterialImportError("independent arXiv V4 import sequence is incomplete")
    expected_inputs = (
        (
            1,
            "derive_distinct_method_origin_paper_candidates",
            Path(
                "project_state/workers/arxiv_expansion_materials/identity_review/"
                "method_origin_candidate_inputs.json"
            ),
            "qrh-method-origin-candidate-input/v1",
            4_420,
            "9240f29e38f54d912d8c4462ae0c3c94f4294c1a2dda8bbfe3d0c4284f419c52",
        ),
        (
            2,
            "plan_or_apply_reviewed_exact_arxiv_resolution_cases",
            Path(
                "project_state/workers/arxiv_expansion_materials/total_resolution_seed.json"
            ),
            "qrh-evidence-resolution-seed/v1",
            6_213,
            "64e3d64657e438e4a7efe36594ad56026133e132ee6aa94fb977620958c2e21b",
        ),
    )
    for row, (step, kind, relative, schema, size, digest) in zip(
        import_sequence, expected_inputs, strict=True
    ):
        if not isinstance(row, Mapping):
            raise ReviewedMaterialImportError("independent arXiv V4 import step is malformed")
        descriptor = row.get("input")
        reconciliation = row.get("descriptor_reconciliation")
        if (
            row.get("step") != step
            or row.get("kind") != kind
            or not isinstance(descriptor, Mapping)
            or descriptor.get("bytes") != size
            or descriptor.get("sha256") != digest
            or not isinstance(reconciliation, Mapping)
            or reconciliation.get("exact_index_match") is not True
            or reconciliation.get("exact_actual_match") is not True
            or reconciliation.get("verdict") != "PASS"
            or (step == 2 and row.get("apply_requires_explicit_var_root") is not True)
        ):
            raise ReviewedMaterialImportError(
                f"independent arXiv V4 import step {step} is not exact"
            )
        verify_workspace_descriptor(
            descriptor,
            label=f"V4 import step {step}",
            expected_relative=relative,
            expected_schema=schema,
        )

    expected_semantic_sets = {
        "new_identity_candidate_ids": {
            "P006", "P008", "P028", "P030", "P032", "P034", "P035", "P036",
            "P037", "P098", "P102", "P108", "P110", "P120", "P153", "P171",
            "P178", "P182",
        },
        "formal_candidate_ids": {
            "P005", "P006", "P008", "P012", "P013", "P028", "P030", "P032",
            "P034", "P035", "P036", "P037", "P054", "P098", "P102", "P108",
            "P110", "P120", "P153", "P171", "P178", "P182",
        },
        "method_original_candidate_ids": {
            "P135", "P137", "P138", "P139", "P143", "P144", "P145",
        },
        "method_derived_candidate_ids": {
            "P135::origin:1909.04939", "P137::origin:2012.08791",
            "P138::origin:1905.10437", "P139::origin:2211.14730",
            "P143::origin:2106.10466", "P144::origin:2106.00750",
            "P145::origin:2202.01575",
        },
        "version_family_hold_candidate_ids": {"P004", "P126", "P169", "P170"},
    }
    if (
        semantic_sets.get("verdict") != "PASS"
        or semantic_sets.get("identity_or_relation_semantics_changed") is not False
        or semantic_sets.get("method_original_ledger_occurrences") != 547
        or any(
            set(semantic_sets.get(key) or []) != expected
            for key, expected in expected_semantic_sets.items()
        )
    ):
        raise ReviewedMaterialImportError("independent arXiv V4 semantic sets changed")

    canonical_results = verdict.get("canonical_identity_results")
    hold_results = verdict.get("version_family_hold_results")
    material_packages = verdict.get("material_packages")
    if (
        not isinstance(canonical_results, list)
        or len(canonical_results) != 18
        or {str(row.get("candidate_id")) for row in canonical_results if isinstance(row, Mapping)}
        != expected_semantic_sets["new_identity_candidate_ids"]
        or any(
            not isinstance(row, Mapping)
            or row.get("passed") is not True
            or row.get("no_baseline_or_crossref_collision") is not True
            for row in canonical_results
        )
        or not isinstance(hold_results, list)
        or len(hold_results) != 4
        or {str(row.get("candidate_id")) for row in hold_results if isinstance(row, Mapping)}
        != expected_semantic_sets["version_family_hold_candidate_ids"]
        or any(
            not isinstance(row, Mapping)
            or row.get("passed") is not True
            or row.get("excluded_from_seed") is not True
            or row.get("importer_eligible") is not False
            or row.get("merge_performed") is not False
            for row in hold_results
        )
        or not isinstance(material_packages, list)
        or len(material_packages) != 29
        or any(
            not isinstance(row, Mapping) or row.get("verdict") != "PASS"
            for row in material_packages
        )
    ):
        raise ReviewedMaterialImportError("independent arXiv V4 identity/material audit failed")

    closure = verdict.get("v1_defect_closure")
    v2_history = verdict.get("v2_history")
    v3_history = verdict.get("v3_incident_history")
    if (
        not isinstance(closure, Mapping)
        or set(closure) != {"D-001", "D-002", "D-003", "D-004"}
        or any(
            not isinstance(row, Mapping)
            or row.get("status") != "CLOSED"
            or row.get("verdict") != "PASS"
            for row in closure.values()
        )
        or not isinstance(v2_history, Mapping)
        or v2_history.get("overall_status") != "FAIL"
        or v2_history.get("release_authorized") is not False
        or not isinstance(v3_history, Mapping)
        or v3_history.get("defect_id") != "V3-D-001"
        or v3_history.get("status") != "CLOSED_IN_V4"
        or v3_history.get("release_blocking_in_v3") is not True
        or v3_history.get("identity_or_relation_semantics_changed") is not False
        or v3_history.get("material_bytes_changed") is not False
        or v3_history.get("verdict") != "PASS"
    ):
        raise ReviewedMaterialImportError("independent arXiv historical defects are not closed")

    remediation_artifacts = verdict.get("v4_remediation_artifacts")
    if not isinstance(remediation_artifacts, list) or len(remediation_artifacts) != 4:
        raise ReviewedMaterialImportError("independent arXiv V4 remediation evidence is incomplete")
    for index, descriptor in enumerate(remediation_artifacts, start=1):
        verify_workspace_descriptor(descriptor, label=f"V4 remediation artifact {index}")

    rights = verdict.get("rights")
    if not isinstance(rights, Mapping):
        raise ReviewedMaterialImportError("independent arXiv V4 rights audit is missing")
    cc_rows = rights.get("cc_by_4_0_attribution_controlled")
    blocked_rows = rights.get("blocked_from_managed_storage")
    if (
        rights.get("verdict") != "PASS"
        or rights.get("policy_rows") != 29
        or rights.get("rights_recording_is_not_a_grant") is not True
        or not isinstance(cc_rows, list)
        or {str(row.get("candidate_id")) for row in cc_rows if isinstance(row, Mapping)}
        != {"P120", "P145", "P171"}
        or any(
            not isinstance(row, Mapping)
            or row.get("verdict") != "PASS"
            or row.get("license_class") != "CC BY 4.0"
            or row.get("redistribution_authorized_by_this_audit") is not False
            for row in cc_rows
        )
        or not isinstance(blocked_rows, list)
        or {str(row.get("candidate_id")) for row in blocked_rows if isinstance(row, Mapping)}
        != {"P034", "P137", "P143"}
        or any(
            not isinstance(row, Mapping)
            or row.get("passed") is not True
            or row.get("acquisition_decision") != "blocked_from_managed_storage"
            or row.get("serving_decision")
            != "metadata_and_official_external_link_only"
            for row in blocked_rows
        )
    ):
        raise ReviewedMaterialImportError("independent arXiv V4 rights boundary changed")

    independence = verdict.get("audit_independence")
    database_boundary = verdict.get("database_boundary")
    if (
        not isinstance(independence, Mapping)
        or independence.get("network_access_used") is not False
        or independence.get("producer_pass_inherited") is not False
        or independence.get("producer_validator_executed") is not False
        or independence.get("sqlite_connection_opened") is not False
        or independence.get("subject_or_material_write_performed") is not False
        or independence.get("database_write_performed") is not False
        or independence.get("reference_write_performed") is not False
        or independence.get("final_full_rerun_from_start") is not True
        or not isinstance(database_boundary, Mapping)
        or database_boundary.get("database_probe_performed") is not False
        or database_boundary.get("sqlite_connection_opened") is not False
        or database_boundary.get("database_write_performed") is not False
        or database_boundary.get("raw_identity_verified_unchanged") is not True
        or database_boundary.get("live_hash_used_as_import_success_evidence") is not False
        or database_boundary.get("verdict") != "PASS"
        or source_integrity.get("reference_modified") is not False
        or source_integrity.get("verdict") != "PASS"
    ):
        raise ReviewedMaterialImportError("independent arXiv V4 audit boundary failed")

    evidence_files = verdict.get("evidence_files")
    if not isinstance(evidence_files, Mapping):
        raise ReviewedMaterialImportError("independent arXiv V4 evidence files are missing")
    evidence_path = verify_workspace_descriptor(
        evidence_files.get("audit_evidence"),
        label="independent V4 audit evidence",
        expected_relative=Path(
            "project_state/workers/independent_arxiv_verifier_v2/audit_evidence_v4.json"
        ),
    )
    if (
        not isinstance(evidence_files.get("audit_evidence"), Mapping)
        or evidence_files["audit_evidence"].get("bytes") != 131_688
        or evidence_files["audit_evidence"].get("sha256")
        != ARXIV_INDEPENDENT_AUDIT_EVIDENCE_V4_SHA256
    ):
        raise ReviewedMaterialImportError("independent V4 audit evidence identity changed")
    for key in ("audit_entry", "audit_implementation"):
        verify_workspace_descriptor(
            evidence_files.get(key), label=f"independent V4 {key}"
        )
    audit_evidence = _json_object(evidence_path)
    if (
        audit_evidence.get("schema_version")
        != "qrh-independent-arxiv-audit-evidence/v4"
        or audit_evidence.get("core_audit_status") != "PASS"
        or audit_evidence.get("checks_total") != 673
        or audit_evidence.get("checks_passed") != 673
        or audit_evidence.get("release_blocking_errors") != []
    ):
        raise ReviewedMaterialImportError("independent V4 audit evidence did not pass")

    if (
        verdict.get("overall_status") != "PASS"
        or verdict.get("release_authorized") is not True
        or defects != []
    ):
        raise ReviewedMaterialImportError(
            "independent arXiv V4 gate has not authorized this delivery"
        )


def _arxiv_reviewed_bundle(sources: ReviewedMaterialSources) -> _ArxivReviewedBundle:
    material_paths = (sources.arxiv_materials_manifest,)
    reading_paths = (sources.arxiv_reading_records,)
    seed_path = sources.arxiv_resolution_seed
    method_inputs_path = sources.arxiv_method_origin_inputs
    holds: tuple[dict[str, object], ...] = ()
    seed_by_paper_source: dict[str, dict[str, object]] = {}

    if sources.arxiv_total_delivery_manifest is not None:
        delivery_path = sources.arxiv_total_delivery_manifest
        delivery = _json_object(delivery_path)
        if delivery.get("schema_version") != "qrh-arxiv-expansion-delivery/v1":
            raise ReviewedMaterialImportError(
                f"{delivery_path}: unsupported arXiv total delivery schema"
            )
        production_hash = str(
            delivery.get("production_database_sha256_verified_unchanged") or ""
        )
        legacy_unchanged_proof = len(production_hash) == 64 and all(
            value in "0123456789abcdef" for value in production_hash.casefold()
        )
        production_boundary = delivery.get("production_database_boundary")
        remediation_no_access_proof = (
            isinstance(production_boundary, Mapping)
            and production_boundary.get("remediation_database_access_performed") is False
            and production_boundary.get("live_database_hash_not_used_as_release_evidence")
            is True
            and production_boundary.get(
                "prior_unchanged_claim_invalidated_by_independent_verifier_D_005"
            )
            is True
        )
        if delivery.get("database_write_performed") is not False or not (
            legacy_unchanged_proof or remediation_no_access_proof
        ):
            raise ReviewedMaterialImportError(
                "arXiv total delivery does not prove its no-production-write boundary"
            )
        files = delivery.get("files")
        if not isinstance(files, Mapping):
            raise ReviewedMaterialImportError("arXiv total delivery has no files index")
        resolved_entries: dict[str, list[dict[str, object]]] = {}
        for group, raw_entries in files.items():
            if not isinstance(raw_entries, list):
                raise ReviewedMaterialImportError(
                    f"arXiv total delivery file group {group!r} is not an array"
                )
            resolved: list[dict[str, object]] = []
            for raw in raw_entries:
                if not isinstance(raw, dict):
                    raise ReviewedMaterialImportError(
                        f"arXiv total delivery file group {group!r} contains a non-object"
                    )
                path = _resolve_delivery_artifact(delivery_path, raw.get("path"))
                _verified_artifact(
                    path,
                    expected_sha256=str(raw.get("sha256") or ""),
                    expected_bytes=int(raw.get("bytes") or -1),
                )
                resolved.append({**raw, "resolved_path": path})
            resolved_entries[str(group)] = resolved
        first = resolved_entries.get("first_batch_official_materials", [])
        new = resolved_entries.get("new_exact_official_materials", [])
        contracts = resolved_entries.get("importer_contracts", [])
        first_material = _select_delivery_entry(
            first, schema_version="qrh-arxiv-expansion-material-manifest/v1"
        )
        first_reading = _select_delivery_entry(
            first,
            schema_version="qrh-arxiv-source-bounded-reading/v1",
            name="reading_records.json",
        )
        new_material = _select_delivery_entry(
            new, schema_version="qrh-arxiv-new-exact-materials/v1"
        )
        new_reading = _select_delivery_entry(
            new,
            schema_version="qrh-arxiv-source-bounded-reading/v1",
            name="reading_records.json",
        )
        total_seed = _select_delivery_entry(
            contracts,
            schema_version="qrh-evidence-resolution-seed/v1",
            name="total_resolution_seed.json",
        )
        method_inputs = _select_delivery_entry(
            contracts, schema_version="qrh-method-origin-candidate-input/v1"
        )
        import_sequence = delivery.get("import_sequence")
        if not isinstance(import_sequence, list) or len(import_sequence) != 2:
            raise ReviewedMaterialImportError(
                "arXiv total delivery must expose the two-step reviewed import sequence"
            )
        sequence_by_step = {
            int(row.get("step") or 0): row
            for row in import_sequence
            if isinstance(row, Mapping)
        }
        if set(sequence_by_step) != {1, 2}:
            raise ReviewedMaterialImportError(
                "arXiv total delivery import sequence steps are incomplete or duplicated"
            )
        for step, expected_entry, expected_kind in (
            (1, method_inputs, "derive_distinct_method_origin_paper_candidates"),
            (2, total_seed, "plan_or_apply_reviewed_exact_arxiv_resolution_cases"),
        ):
            sequence_row = sequence_by_step[step]
            sequence_input = sequence_row.get("input")
            if (
                sequence_row.get("kind") != expected_kind
                or not isinstance(sequence_input, Mapping)
                or any(
                    sequence_input.get(key) != expected_entry.get(key)
                    for key in ("path", "schema_version", "sha256", "bytes")
                )
            ):
                raise ReviewedMaterialImportError(
                    f"arXiv import sequence step {step} is stale or not file-index bound"
                )
        if sequence_by_step[2].get("apply_requires_explicit_var_root") is not True:
            raise ReviewedMaterialImportError(
                "arXiv resolution import must require an explicit isolated var root"
            )
        material_paths = (
            Path(first_material["resolved_path"]),
            Path(new_material["resolved_path"]),
        )
        reading_paths = (
            Path(first_reading["resolved_path"]),
            Path(new_reading["resolved_path"]),
        )
        referenced_seed = Path(total_seed["resolved_path"])
        referenced_method_inputs = Path(method_inputs["resolved_path"])
        if seed_path is not None and seed_path.resolve() != referenced_seed.resolve():
            raise ReviewedMaterialImportError(
                "explicit arXiv resolution seed differs from total delivery contract"
            )
        if (
            method_inputs_path is not None
            and method_inputs_path.resolve() != referenced_method_inputs.resolve()
        ):
            raise ReviewedMaterialImportError(
                "explicit method-origin inputs differ from total delivery contract"
            )
        seed_path = referenced_seed
        method_inputs_path = referenced_method_inputs
        raw_holds = delivery.get("version_family_relationships")
        if not isinstance(raw_holds, list) or len(raw_holds) != 4:
            raise ReviewedMaterialImportError(
                "arXiv total delivery must preserve four version-family holds"
            )
        holds = tuple(dict(row) for row in raw_holds if isinstance(row, dict))
        if len(holds) != 4 or any(
            row.get("importer_eligible") is not False
            or row.get("merge_performed") is not False
            or row.get("relation_kind")
            != "same_candidate_version_family_signal_unmerged"
            for row in holds
        ):
            raise ReviewedMaterialImportError(
                "arXiv version-family holds are not fail-closed"
            )

    _validate_arxiv_independent_gate(
        sources.arxiv_independent_verdict,
        delivery_path=sources.arxiv_total_delivery_manifest,
    )

    materials: dict[str, tuple[Path, dict[str, object]]] = {}
    for path in material_paths:
        root, rows = _material_items(path)
        for source_id, row in rows.items():
            if source_id in materials:
                raise ReviewedMaterialImportError(
                    f"duplicate arXiv material across delivery packages: {source_id}"
                )
            materials[source_id] = (root, row)
    readings: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for path in reading_paths:
        payload = _json_object(path)
        rows = payload.get("items")
        boundary = payload.get("fact_boundary")
        if not isinstance(rows, list) or not (
            isinstance(boundary, Mapping)
            or isinstance(boundary, str) and boundary.strip()
        ):
            raise ReviewedMaterialImportError(
                f"{path}: arXiv reading contract lacks items/fact_boundary"
            )
        normalized_boundary = (
            dict(boundary)
            if isinstance(boundary, Mapping)
            else {"statement": str(boundary).strip()}
        )
        for row in rows:
            if not isinstance(row, dict):
                raise ReviewedMaterialImportError(
                    f"{path}: arXiv reading item must be an object"
                )
            source_id = str(row.get("source_candidate_id") or "")
            if not source_id or source_id in readings:
                raise ReviewedMaterialImportError(
                    f"invalid or duplicate arXiv reading source: {source_id!r}"
                )
            readings[source_id] = (row, normalized_boundary)
    if set(materials) != set(readings):
        raise ReviewedMaterialImportError(
            "arXiv material and reading packages do not have the same closed source set"
        )

    if seed_path is not None:
        seed = _json_object(seed_path)
        if seed.get("schema_version") != "qrh-evidence-resolution-seed/v1":
            raise ReviewedMaterialImportError(f"{seed_path}: unsupported resolution seed")
        seed_items = seed.get("items")
        if not isinstance(seed_items, list):
            raise ReviewedMaterialImportError(f"{seed_path}: resolution seed has no items")
        for row in seed_items:
            if not isinstance(row, Mapping):
                raise ReviewedMaterialImportError("arXiv resolution seed item is not an object")
            source_id = str(row.get("source_candidate_id") or "")
            if not source_id or source_id in seed_by_paper_source:
                raise ReviewedMaterialImportError(
                    f"invalid or duplicate arXiv resolution seed source: {source_id!r}"
                )
            seed_by_paper_source[source_id] = dict(row)
        observed_paper_sources: set[str] = set()
        formal = 0
        associated = 0
        for source_id, (_, material) in materials.items():
            reading, _ = readings[source_id]
            relation = reading.get("archive_relation")
            if not isinstance(relation, Mapping):
                raise ReviewedMaterialImportError(f"{source_id}: reading relation malformed")
            paper_source_id = str(relation.get("paper_source_candidate_id") or "")
            observed_paper_sources.add(paper_source_id)
            seed_row = seed_by_paper_source.get(paper_source_id)
            if seed_row is None:
                raise ReviewedMaterialImportError(
                    f"{source_id}: total resolution seed omits {paper_source_id}"
                )
            seed_arxiv = normalize_identifier("arxiv", str(seed_row.get("arxiv_id") or ""))
            reading_arxiv = normalize_identifier("arxiv", str(reading.get("arxiv_id") or ""))
            material_arxiv = normalize_identifier("arxiv", str(material.get("seed_arxiv_id") or ""))
            official = material.get("official_metadata")
            if not isinstance(official, Mapping):
                raise ReviewedMaterialImportError(f"{source_id}: official metadata malformed")
            if seed_arxiv != reading_arxiv or seed_arxiv != material_arxiv:
                raise ReviewedMaterialImportError(
                    f"{source_id}: seed/material/reading arXiv identifiers diverge"
                )
            if str(seed_row.get("label") or "").strip() != str(
                official.get("title") or ""
            ).strip():
                raise ReviewedMaterialImportError(
                    f"{source_id}: seed label differs from official material title"
                )
            treatment = str(relation.get("treatment") or "")
            if treatment == "formal_citation":
                formal += 1
                if paper_source_id != source_id:
                    raise ReviewedMaterialImportError(
                        f"{source_id}: formal citation cannot resolve through another source candidate"
                    )
            elif treatment == "associated_method_origin":
                associated += 1
                if paper_source_id == source_id:
                    raise ReviewedMaterialImportError(
                        f"{source_id}: associated method origin requires a distinct paper candidate"
                    )
            else:
                raise ReviewedMaterialImportError(
                    f"{source_id}: unsupported total delivery treatment {treatment!r}"
                )
        if (
            set(seed_by_paper_source) != observed_paper_sources
            or len(seed_by_paper_source) != 29
            or formal != 22
            or associated != 7
        ):
            raise ReviewedMaterialImportError(
                "arXiv total delivery closed set must be 29 = 22 formal + 7 associated"
            )
        forbidden = {str(row.get("candidate_id") or "") for row in holds} | {"P095"}
        if forbidden & set(seed_by_paper_source):
            raise ReviewedMaterialImportError(
                "arXiv total resolution seed contains a held or denied source candidate"
            )

    return _ArxivReviewedBundle(
        material_paths=material_paths,
        reading_paths=reading_paths,
        materials=materials,
        readings=readings,
        resolution_seed_path=seed_path,
        resolution_seed=seed_by_paper_source,
        method_origin_inputs_path=method_inputs_path,
        version_family_holds=holds,
    )


def _request_artifact(
    materials_root: Path,
    item: Mapping[str, object],
    kind: str,
) -> tuple[dict[str, object], bytes]:
    requests = item.get("requests")
    artifacts = item.get("artifacts")
    if not isinstance(requests, Mapping) or not isinstance(artifacts, Mapping):
        raise ReviewedMaterialImportError("arXiv item lacks request/artifact receipts")
    request_path = _resolve_artifact(materials_root, requests[kind])
    request = _json_object(request_path)
    body_path = _resolve_artifact(materials_root, request.get("body_path") or artifacts[kind])
    expected_hash = str(request.get("sha256") or "")
    payload = _verified_artifact(
        body_path,
        expected_sha256=expected_hash,
        expected_bytes=int(request.get("bytes") or -1),
    )
    if not request.get("successful") or int(request.get("http_status") or 0) != 200:
        raise ReviewedMaterialImportError(f"arXiv {kind} receipt is not successful")
    return request, payload


def _include_arxiv_source(
    source_id: str,
    reading: Mapping[str, object],
    include_source_candidates: frozenset[str] | None,
) -> bool:
    if include_source_candidates is None:
        return True
    relation = reading.get("archive_relation")
    paper_source_id = (
        str(relation.get("paper_source_candidate_id") or "")
        if isinstance(relation, Mapping)
        else ""
    )
    return source_id in include_source_candidates or paper_source_id in include_source_candidates


def _validate_arxiv_reading_locators(
    *,
    source_id: str,
    reading: Mapping[str, object],
    material: Mapping[str, object],
    materials_root: Path,
) -> int:
    validation = material.get("pdf_validation")
    artifacts = material.get("artifacts")
    if not isinstance(validation, Mapping) or not isinstance(artifacts, Mapping):
        raise ReviewedMaterialImportError(
            f"{source_id}: material lacks PDF validation/artifact facts"
        )
    page_rows = validation.get("page_text")
    if not isinstance(page_rows, list):
        raise ReviewedMaterialImportError(f"{source_id}: material has no page hashes")
    page_hashes = {
        str(int(row["page"])): str(row["text_sha256"])
        for row in page_rows
        if isinstance(row, Mapping)
    }
    pdf_request, _ = _request_artifact(materials_root, material, "pdf")
    source_pdf_sha256 = str(pdf_request.get("sha256") or "")
    extracted_text_sha256 = str(validation.get("text_sha256") or "")
    if len(page_hashes) != len(page_rows) or len(source_pdf_sha256) != 64 or len(
        extracted_text_sha256
    ) != 64:
        raise ReviewedMaterialImportError(
            f"{source_id}: material PDF/page/text hashes are incomplete"
        )

    claims: list[Mapping[str, object]] = []
    core_problem = reading.get("core_problem")
    if isinstance(core_problem, Mapping):
        claims.append(core_problem)
    for field in ("method", "main_findings", "applicability_boundaries"):
        values = reading.get(field)
        if isinstance(values, list):
            claims.extend(value for value in values if isinstance(value, Mapping))
    locator_count = 0
    for claim in claims:
        evidence_rows = claim.get("evidence")
        if claim.get("status") == "source_finding" and (
            not isinstance(evidence_rows, list) or not evidence_rows
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: source finding has no evidence locator"
            )
        if evidence_rows in (None, [], ()):
            continue
        if not isinstance(evidence_rows, list):
            raise ReviewedMaterialImportError(
                f"{source_id}: claim evidence locators are not an array"
            )
        for evidence in evidence_rows:
            if not isinstance(evidence, Mapping):
                raise ReviewedMaterialImportError(
                    f"{source_id}: claim evidence locator is not an object"
                )
            pages = evidence.get("pdf_pages")
            by_page = evidence.get("page_text_sha256_by_page")
            alias = evidence.get("page_text_sha256")
            if not isinstance(pages, list) or not pages or not isinstance(
                by_page, Mapping
            ) or not isinstance(alias, Mapping):
                raise ReviewedMaterialImportError(
                    f"{source_id}: claim evidence locator lacks v2 page-hash maps"
                )
            expected_keys = {str(int(page)) for page in pages}
            normalized_by_page = {str(key): str(value) for key, value in by_page.items()}
            normalized_alias = {str(key): str(value) for key, value in alias.items()}
            if (
                set(normalized_by_page) != expected_keys
                or set(normalized_alias) != expected_keys
                or normalized_alias != normalized_by_page
                or any(
                    page_hashes.get(page) != value
                    for page, value in normalized_by_page.items()
                )
                or evidence.get("source_pdf_sha256") != source_pdf_sha256
                or evidence.get("extracted_text_sha256") != extracted_text_sha256
                or evidence.get("locator_version")
                != "physical-page+sorted-pymupdf-text-sha256/v2"
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: claim evidence locator is not bound to reviewed PDF pages"
                )
            locator_count += 1
    return locator_count


class ReviewedMaterialImporter:
    """Moves reviewed bytes through 0004 services before 0005 canonicalization.

    SQL in this class is deliberately read-only.  Resolution, provider facts,
    decisions, rights, acquisition, content registration, and canonicalization
    all cross their existing service/repository boundaries.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.repository = EvidenceRepository(settings)
        self.expansion = EvidenceExpansionRepository(settings)
        self.expansion_service = EvidenceExpansionService(settings)
        self.canonicalization = ReviewedEvidenceCanonicalizationService(settings)
        self.resources = EvidenceResourceStore(settings)

    @staticmethod
    def static_plan(
        sources: ReviewedMaterialSources,
        *,
        include_source_candidates: frozenset[str] | None = None,
    ) -> dict[str, object]:
        """Validate reviewed artifact receipts without opening a database."""

        overrides = _reconciliation_overrides(sources.reconciliation_overrides)
        crossref_rows = _crossref_rows(sources.crossref_decisions)
        identity_verdicts = _crossref_identity_verdict_rows(
            sources.crossref_identity_verdicts,
            decision_rows=crossref_rows,
        )
        rights_rows = _crossref_rights_rows(
            sources.crossref_rights_manifest,
            decision_rows=crossref_rows,
        )
        for source_id, row in crossref_rows.items():
            _validate_crossref_rights_row(
                row,
                rights_rows.get(source_id),
                identity_verdicts.get(source_id),
            )
        fulltext_rows = _crossref_fulltext_rows(
            sources.crossref_fulltext_manifest,
            decision_rows=crossref_rows,
            rights_rows=rights_rows,
        )
        if (
            sources.open_pdf_review_summary is not None
            and include_source_candidates is not None
        ):
            raise ReviewedMaterialImportError(
                "the reviewed open-PDF closed set cannot be partially imported"
            )
        open_pdf_plan, _ = _open_pdf_review_bundle(
            sources.open_pdf_review_summary
        )
        eligible_crossref: list[str] = []
        excluded_crossref: dict[str, str] = {}
        for source_id, row in sorted(crossref_rows.items()):
            if include_source_candidates is not None and source_id not in include_source_candidates:
                continue
            _crossref_body(row)
            identity_allowed = (
                not identity_verdicts
                or identity_verdicts[source_id].get("identity_verdict") == "PASS"
            )
            if _crossref_reconciliation_allows(source_id, overrides) and identity_allowed:
                eligible_crossref.append(source_id)
            else:
                excluded_crossref[source_id] = (
                    str((overrides.get(source_id) or {}).get("rationale") or "")
                    or DEFAULT_CROSSREF_RECONCILIATION_DENYLIST.get(source_id, "")
                    or str(
                        (identity_verdicts.get(source_id) or {}).get("reason") or ""
                    )
                    or "independent identity verifier did not authorize import"
                )

        crossref_official_abstracts: list[dict[str, object]] = []
        for source_id in eligible_crossref:
            try:
                excerpt = reviewed_crossref_official_abstract_excerpt(
                    crossref_rows[source_id]
                )
            except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
                raise ReviewedMaterialImportError(
                    f"{source_id}: official Crossref deposit abstract evidence is invalid"
                ) from error
            if excerpt is None:
                continue
            locator = excerpt.locator
            if (
                locator.get("normalization_contract")
                != CROSSREF_DEPOSIT_ABSTRACT_NORMALIZATION
                or not str(locator.get("source_path") or "").startswith(
                    "project_state/"
                )
                or locator.get("normalized_excerpt_sha256")
                != _sha256(excerpt.text.encode("utf-8"))
                or int(locator.get("normalized_excerpt_bytes") or -1)
                != len(excerpt.text.encode("utf-8"))
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: official Crossref abstract locator is not canonical"
                )
            crossref_official_abstracts.append(
                {
                    "source_candidate_id": source_id,
                    "paper_source_candidate_id": source_id,
                    "normalized_identifier": str(
                        locator["normalized_identifier"]
                    ),
                    "title": str(locator["title"]),
                    "excerpt_sha256": str(locator["normalized_excerpt_sha256"]),
                    "excerpt_bytes": int(locator["normalized_excerpt_bytes"]),
                    "source_path": str(locator["source_path"]),
                    "source_file_sha256": str(locator["source_file_sha256"]),
                    "source_file_bytes": int(locator["source_file_bytes"]),
                }
            )
        if (
            len(
                {str(row["normalized_identifier"]) for row in crossref_official_abstracts}
            )
            != len(crossref_official_abstracts)
            or len({str(row["source_path"]) for row in crossref_official_abstracts})
            != len(crossref_official_abstracts)
        ):
            raise ReviewedMaterialImportError(
                "reviewed Crossref official abstract projection is duplicated"
            )

        rights_ready = [
            source_id
            for source_id in eligible_crossref
            if int((rights_rows.get(source_id) or {}).get("verified_open_pdf_offer_count") or 0) > 0
            and source_id not in fulltext_rows
        ]
        if identity_verdicts and sources.crossref_fulltext_manifest is not None and (
            rights_ready != [] or sorted(fulltext_rows) != ["U055"]
        ):
            raise ReviewedMaterialImportError(
                "reviewed Crossref closed set requires no pending rights-ready item "
                "and exactly U055 failed closed after GET"
            )

        bundle = _arxiv_reviewed_bundle(sources)
        materials = bundle.materials
        reading_by_source = {
            source_id: row for source_id, (row, _) in bundle.readings.items()
        }
        formal = 0
        associated = 0
        arxiv_storage_approved: list[str] = []
        arxiv_metadata_only: list[str] = []
        arxiv_license_blocked: list[str] = []
        selected_arxiv: list[str] = []
        arxiv_official_abstracts: list[dict[str, object]] = []
        arxiv_hash_anchored_locators = 0
        for source_id, (materials_root, item) in sorted(materials.items()):
            if source_id not in reading_by_source:
                raise ReviewedMaterialImportError(
                    f"{source_id}: material has no reviewed reading record"
                )
            reading = reading_by_source[source_id]
            if not _include_arxiv_source(
                source_id, reading, include_source_candidates
            ):
                continue
            _, atom_payload = _request_artifact(materials_root, item, "atom")
            try:
                official_excerpt = reviewed_arxiv_official_abstract_excerpt(
                    materials_root, item
                )
                if normalize_arxiv_atom_summary(atom_payload) != official_excerpt.text:
                    raise ValueError(
                        "request-bound Atom summary differs from builder source evidence"
                    )
            except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
                raise ReviewedMaterialImportError(
                    f"{source_id}: official Atom abstract evidence is invalid"
                ) from error
            excerpt_locator = official_excerpt.locator
            if (
                excerpt_locator.get("normalization_contract")
                != ARXIV_ATOM_SUMMARY_NORMALIZATION
                or not str(excerpt_locator.get("source_path") or "").startswith(
                    "project_state/"
                )
                or excerpt_locator.get("normalized_excerpt_sha256")
                != _sha256(official_excerpt.text.encode("utf-8"))
                or int(excerpt_locator.get("normalized_excerpt_bytes") or -1)
                != len(official_excerpt.text.encode("utf-8"))
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: official Atom abstract locator is not canonical"
                )
            arxiv_official_abstracts.append(
                {
                    "source_candidate_id": source_id,
                    "paper_source_candidate_id": str(
                        (reading.get("archive_relation") or {}).get(
                            "paper_source_candidate_id"
                        )
                        or ""
                    ),
                    "normalized_identifier": str(
                        excerpt_locator["normalized_identifier"]
                    ),
                    "title": str(excerpt_locator["title"]),
                    "excerpt_sha256": str(
                        excerpt_locator["normalized_excerpt_sha256"]
                    ),
                    "excerpt_bytes": int(
                        excerpt_locator["normalized_excerpt_bytes"]
                    ),
                    "source_path": str(excerpt_locator["source_path"]),
                    "source_file_sha256": str(
                        excerpt_locator["source_file_sha256"]
                    ),
                    "source_file_bytes": int(
                        excerpt_locator["source_file_bytes"]
                    ),
                }
            )
            _, pdf = _request_artifact(materials_root, item, "pdf")
            if not pdf.startswith(b"%PDF-"):
                raise ReviewedMaterialImportError(f"{source_id}: PDF magic is invalid")
            rights = item.get("rights")
            rights_status = (
                str(rights.get("rights_status") or "")
                if isinstance(rights, Mapping)
                else ""
            )
            if not isinstance(rights, Mapping) or rights.get(
                "redistribution_authorized_by_this_audit"
            ) is not False:
                raise ReviewedMaterialImportError(
                    f"{source_id}: arXiv audit must not imply redistribution authorization"
                )
            expected_decisions = ARXIV_RIGHTS_DECISION_CONTRACT.get(rights_status)
            if expected_decisions is not None and (
                rights.get("acquisition_decision") != expected_decisions[0]
                or rights.get("serving_decision") != expected_decisions[1]
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: rights status and acquisition/serving decisions disagree"
                )
            reading_rights = reading.get("rights_boundary")
            if not isinstance(reading_rights, Mapping) or any(
                reading_rights.get(key) != rights.get(key)
                for key in (
                    "rights_status",
                    "acquisition_decision",
                    "serving_decision",
                    "redistribution_authorized_by_this_audit",
                )
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: reading/material rights boundaries disagree"
                )
            embedded_notices = rights.get("embedded_pdf_rights_notices") or []
            if not isinstance(embedded_notices, list):
                raise ReviewedMaterialImportError(
                    f"{source_id}: embedded rights notices must be an array"
                )
            if embedded_notices and rights_status in {
                "repository_distribution_only",
                "verified_open_license",
            }:
                raise ReviewedMaterialImportError(
                    f"{source_id}: embedded restrictive rights evidence was not consumed"
                )
            if rights_status.startswith(
                "official_repository_access_with_embedded_"
            ) and not embedded_notices:
                raise ReviewedMaterialImportError(
                    f"{source_id}: blocked embedded-rights status has no notice evidence"
                )
            if rights_status == "verified_open_license" and (
                rights.get("license_class") != "CC BY 4.0"
                or "http://creativecommons.org/licenses/by/4.0/"
                not in (rights.get("paper_license_urls") or [])
                or not isinstance(rights.get("license_evidence"), list)
                or not rights.get("license_evidence")
                or not isinstance(rights.get("attribution_requirements"), list)
                or not rights.get("attribution_requirements")
            ):
                raise ReviewedMaterialImportError(
                    f"{source_id}: verified CC BY 4.0 rights lack license/attribution evidence"
                )
            if rights_status in {"repository_distribution_only", "verified_open_license"}:
                arxiv_storage_approved.append(source_id)
            elif rights_status == "official_repository_access_no_per_paper_license_exposed":
                arxiv_metadata_only.append(source_id)
            elif rights_status in {
                "official_repository_access_with_embedded_no_redistribution_notice",
                "official_repository_access_with_embedded_limited_reproduction_notice",
                "official_repository_access_with_embedded_all_rights_reserved_notice",
            }:
                arxiv_license_blocked.append(source_id)
            else:
                raise ReviewedMaterialImportError(
                    f"{source_id}: unsupported reviewed rights status {rights_status!r}"
                )
            relation = reading.get("archive_relation") or {}
            treatment = str(relation.get("treatment") or "") if isinstance(relation, Mapping) else ""
            if treatment == "formal_citation":
                formal += 1
            elif treatment == "associated_method_origin":
                associated += 1
            else:
                raise ReviewedMaterialImportError(
                    f"{source_id}: unsupported reviewed relation treatment {treatment!r}"
                )
            selected_arxiv.append(source_id)
            if sources.arxiv_independent_verdict is not None:
                arxiv_hash_anchored_locators += _validate_arxiv_reading_locators(
                    source_id=source_id,
                    reading=reading,
                    material=item,
                    materials_root=materials_root,
                )
        if (
            len(arxiv_official_abstracts) != len(selected_arxiv)
            or {str(row["source_candidate_id"]) for row in arxiv_official_abstracts}
            != set(selected_arxiv)
            or len(
                {str(row["normalized_identifier"]) for row in arxiv_official_abstracts}
            )
            != len(arxiv_official_abstracts)
            or len({str(row["source_path"]) for row in arxiv_official_abstracts})
            != len(arxiv_official_abstracts)
        ):
            raise ReviewedMaterialImportError(
                "reviewed arXiv official abstract projection is incomplete or duplicated"
            )
        return {
            "mode": "plan_only",
            "database_opened": False,
            "crossref_reviewed": len(
                [
                    source_id
                    for source_id in crossref_rows
                    if include_source_candidates is None or source_id in include_source_candidates
                ]
            ),
            "crossref_eligible": len(eligible_crossref),
            "crossref_eligible_source_candidates": eligible_crossref,
            "crossref_excluded": excluded_crossref,
            "crossref_rights_ready_without_pdf_bytes": rights_ready,
            "crossref_fulltext_failed_closed": sorted(fulltext_rows),
            "crossref_tier_reconciled": sorted(
                source_id
                for source_id, verdict in identity_verdicts.items()
                if isinstance(verdict.get("tier_review"), Mapping)
                and verdict["tier_review"].get("as_produced")
                != verdict["tier_review"].get("required")
                and verdict.get("identity_verdict") == "PASS"
            ),
            "crossref_official_metadata_conflicts": sorted(
                source_id
                for source_id, verdict in identity_verdicts.items()
                if verdict.get("notes")
                and source_id == "P033"
            ),
            "crossref_official_abstracts_verified": len(
                crossref_official_abstracts
            ),
            "crossref_official_abstract_normalization_contract": (
                CROSSREF_DEPOSIT_ABSTRACT_NORMALIZATION
            ),
            "crossref_official_abstract_projection": crossref_official_abstracts,
            "crossref_official_abstract_projection_sha256": _sha256(
                canonical_json(crossref_official_abstracts).encode("utf-8")
            ),
            "open_pdf_review": open_pdf_plan,
            "open_pdf_reviewed_count": (
                int(open_pdf_plan["reviewed_count"])
                if open_pdf_plan is not None
                else 0
            ),
            "open_pdf_allowed_resources": (
                int(open_pdf_plan["allowed_count"])
                if open_pdf_plan is not None
                else 0
            ),
            "open_pdf_fail_closed": (
                int(open_pdf_plan["fail_closed_count"])
                if open_pdf_plan is not None
                else 0
            ),
            "open_pdf_allowed_projection_sha256": (
                str(open_pdf_plan["allowed_projection_sha256"])
                if open_pdf_plan is not None
                else None
            ),
            "arxiv_reviewed": len(selected_arxiv),
            "arxiv_official_abstracts_verified": len(arxiv_official_abstracts),
            "arxiv_official_abstract_normalization_contract": (
                ARXIV_ATOM_SUMMARY_NORMALIZATION
            ),
            "arxiv_official_abstract_projection": arxiv_official_abstracts,
            "arxiv_official_abstract_projection_sha256": _sha256(
                canonical_json(arxiv_official_abstracts).encode("utf-8")
            ),
            "arxiv_formal_citations": formal,
            "arxiv_associated_method_origins": associated,
            "arxiv_verified_pdf_artifacts": len(selected_arxiv),
            "arxiv_storage_approved": arxiv_storage_approved,
            "arxiv_metadata_only": arxiv_metadata_only,
            "arxiv_license_blocked": arxiv_license_blocked,
            "arxiv_resolution_seed_rows": (
                len(_json_object(bundle.resolution_seed_path).get("items", []))
                if bundle.resolution_seed_path is not None
                else None
            ),
            "arxiv_version_family_holds": [
                str(row.get("candidate_id") or "")
                for row in bundle.version_family_holds
            ],
            "arxiv_hash_anchored_reading_locators": arxiv_hash_anchored_locators,
        }

    def _candidate_id(self, source_candidate_id: str) -> str:
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT candidate.candidate_id
                FROM paper_clue AS clue
                JOIN paper_clue_candidate AS link USING(clue_id)
                JOIN paper_candidate AS candidate USING(candidate_id)
                WHERE clue.source_candidate_id=? AND link.link_kind='local_claim'
                  AND candidate.candidate_kind='paper'
                ORDER BY candidate.candidate_id
                """,
                (source_candidate_id,),
            ).fetchall()
        if len(rows) != 1:
            raise ReviewedMaterialImportError(
                f"{source_candidate_id}: expected one paper candidate, found {len(rows)}"
            )
        return str(rows[0]["candidate_id"])

    def _case_observation(
        self, case_id: str, *, scheme: str, normalized_identifier: str
    ) -> tuple[str, tuple[str, ...]]:
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT observation.provider_observation_id,
                       observation.normalized_identifiers_json
                FROM evidence_provider_observation AS observation
                JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
                JOIN evidence_provider_request AS request USING(provider_request_id)
                WHERE request.resolution_case_id=?
                  AND observation.match_basis='source_identifier_exact'
                  AND observation.identity_effect='strong_identifier_verified'
                ORDER BY observation.provider_observation_id
                """,
                (case_id,),
            ).fetchall()
            offers = tuple(
                str(row["resource_offer_id"])
                for row in connection.execute(
                    """
                    SELECT offer.resource_offer_id
                    FROM evidence_resource_offer AS offer
                    JOIN evidence_provider_observation AS observation
                      USING(provider_observation_id)
                    JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
                    JOIN evidence_provider_request AS request USING(provider_request_id)
                    WHERE request.resolution_case_id=? ORDER BY offer.resource_offer_id
                    """,
                    (case_id,),
                )
            )
        matching = []
        for row in rows:
            identifiers = json.loads(str(row["normalized_identifiers_json"]))
            if any(
                value.get("scheme") == scheme
                and value.get("normalized_value") == normalized_identifier
                for value in identifiers
            ):
                matching.append(str(row["provider_observation_id"]))
        if len(matching) != 1:
            raise ReviewedMaterialImportError(
                f"{case_id}: expected one exact {scheme} observation, found {len(matching)}"
            )
        return matching[0], offers

    def _existing_decision(
        self, case_id: str, *, scheme: str, normalized_identifier: str
    ) -> str | None:
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT identity_decision_id
                FROM evidence_identity_decision
                WHERE resolution_case_id=?
                  AND decision_kind='accept_verified_identifier'
                  AND identifier_scheme=? AND normalized_identifier=?
                ORDER BY identity_decision_id
                """,
                (case_id, scheme, normalized_identifier),
            ).fetchall()
        if len(rows) > 1:
            raise ReviewedMaterialImportError(
                f"{case_id}: multiple accepted decisions for one reviewed identifier"
            )
        return str(rows[0]["identity_decision_id"]) if rows else None

    def _import_identity(
        self,
        *,
        source_candidate_id: str,
        paper_source_candidate_id: str,
        scheme: str,
        raw_identifier: str,
        adapter: ProviderAdapter,
        response: ProviderHttpResponse,
        rationale: str,
        provenance_urn: str,
    ) -> tuple[str, str, str, tuple[str, ...]]:
        candidate_id = self._candidate_id(paper_source_candidate_id)
        normalized = normalize_identifier(scheme, raw_identifier)
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme=scheme,
                    raw_value=raw_identifier,
                    source_provenance_urn=provenance_urn,
                ),
            )
        )
        opened, requests = self.expansion_service.enqueue_and_plan(
            candidate_id,
            query,
            (adapter,),
            provenance_urn=provenance_urn,
            idempotency_key=f"reviewed-open:{paper_source_candidate_id}:{scheme}:{normalized}",
        )
        state = opened.state
        if state.state == "resolving":
            if len(requests) != 1:
                raise ReviewedMaterialImportError(
                    f"{paper_source_candidate_id}: exact identifier import planned {len(requests)} requests"
                )
            planned = adapter.plan(query)
            if len(planned) != 1 or response.request_url != planned[0].url:
                raise ReviewedMaterialImportError(
                    f"{paper_source_candidate_id}: cached response is not bound to the planned exact request"
                )
            ingested = self.expansion.ingest_provider_response(
                requests[0].provider_request_id,
                response,
                adapter,
                attempt_number=1,
                idempotency_key=(
                    f"reviewed-provider:{paper_source_candidate_id}:{response.body_sha256}"
                ),
                provenance_urn=(
                    f"{provenance_urn}:provider-response:sha256:{response.body_sha256}"
                ),
            )
            if ingested.result_status != "succeeded":
                raise ReviewedMaterialImportError(
                    f"{paper_source_candidate_id}: provider artifact rejected: {ingested.parse_error}"
                )
            state, _ = self.expansion.finalize_provider_cycle(
                opened.resolution_case_id,
                expected_revision=state.revision,
                idempotency_key=(
                    f"reviewed-finalize:{paper_source_candidate_id}:{response.body_sha256}"
                ),
            )
        if state.state not in {"awaiting_review", "identifier_verified"}:
            raise ReviewedMaterialImportError(
                f"{paper_source_candidate_id}: resolution state is {state.state!r}"
            )
        observation_id, offer_ids = self._case_observation(
            opened.resolution_case_id,
            scheme=scheme,
            normalized_identifier=normalized,
        )
        decision_id = self._existing_decision(
            opened.resolution_case_id,
            scheme=scheme,
            normalized_identifier=normalized,
        )
        if state.state == "awaiting_review":
            decision = self.expansion.record_identity_decision(
                opened.resolution_case_id,
                expected_revision=state.revision,
                decision_kind="accept_verified_identifier",
                provider_observation_id=observation_id,
                identifier_scheme=scheme,
                normalized_identifier=normalized,
                authority_kind="human_review",
                rationale=rationale,
                evidence_refs=[observation_id, f"response-sha256:{response.body_sha256}"],
                idempotency_key=(
                    f"reviewed-accept:{paper_source_candidate_id}:{scheme}:{normalized}"
                ),
                provenance_urn=provenance_urn,
                policy_version=IMPORT_POLICY_VERSION,
            )
            decision_id = decision.identity_decision_id
        if decision_id is None:
            raise ReviewedMaterialImportError(
                f"{paper_source_candidate_id}: verified state lacks the explicit reviewed decision"
            )
        return candidate_id, opened.resolution_case_id, decision_id, offer_ids

    def _offer_id(self, case_id: str, expected_url: str) -> str:
        with evidence_connection(self.settings) as connection:
            rows = connection.execute(
                """
                SELECT offer.resource_offer_id
                FROM evidence_resource_offer AS offer
                JOIN evidence_provider_observation AS observation
                  USING(provider_observation_id)
                JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
                JOIN evidence_provider_request AS request USING(provider_request_id)
                WHERE request.resolution_case_id=? AND offer.url=?
                ORDER BY offer.resource_offer_id
                """,
                (case_id, expected_url),
            ).fetchall()
        if len(rows) != 1:
            raise ReviewedMaterialImportError(
                f"{case_id}: expected one reviewed resource offer for {expected_url}, found {len(rows)}"
            )
        return str(rows[0]["resource_offer_id"])

    def _crossref_rights_ready(
        self,
        *,
        source_id: str,
        case_id: str,
        rights_row: Mapping[str, object] | None,
        provenance_urn: str,
    ) -> str:
        if not rights_row or int(rights_row.get("verified_open_pdf_offer_count") or 0) == 0:
            return "metadata_only_no_approved_pdf_offer"
        offers = rights_row.get("official_fulltext_offers")
        if not isinstance(offers, list):
            raise ReviewedMaterialImportError(f"{source_id}: malformed Crossref rights offers")
        approved = [
            offer
            for offer in offers
            if isinstance(offer, Mapping)
            and offer.get("acquisition_status") == "available_verified_open_pdf"
            and offer.get("mime_verified_pdf") is True
        ]
        if len(approved) != 1:
            raise ReviewedMaterialImportError(
                f"{source_id}: expected one reviewed open PDF offer, found {len(approved)}"
            )
        offer = approved[0]
        offer_url = str(offer.get("url") or "")
        offer_id = self._offer_id(case_id, offer_url)
        licenses = offer.get("applicable_open_licenses") or []
        license_urls = [
            str(item.get("url") or "")
            for item in licenses
            if isinstance(item, Mapping) and str(item.get("url") or "").startswith("https://")
        ]
        if not license_urls:
            raise ReviewedMaterialImportError(
                f"{source_id}: approved Crossref offer lacks an HTTPS license fact"
            )
        assessment = self.expansion.record_rights_assessment(
            offer_id,
            RightsAssessmentProposal(
                decision="approved_for_local_storage",
                rights_status="verified_open_license",
                authority_kind="human_review",
                policy_version=IMPORT_POLICY_VERSION,
                legal_basis=(
                    "Reviewed Crossref exact-DOI license metadata and a successful PDF MIME "
                    "probe permit an audited future fetch; HEAD is not a PDF acquisition."
                ),
                evidence={
                    "license_urls": license_urls,
                    "content_version": offer.get("content_version"),
                    "mime_probe": offer.get("mime_probe"),
                    "pdf_bytes_present": False,
                    "fact_boundary": "rights ready; GET/content verification not performed",
                },
            ),
            idempotency_key=f"reviewed-crossref-rights:{source_id}",
            provenance_urn=f"{provenance_urn}:rights:{source_id}",
        )
        acquisition = self.expansion.open_acquisition_case(
            offer_id,
            assessment.rights_assessment_id,
            provenance_urn=f"{provenance_urn}:acquisition-ready:{source_id}",
        )
        if acquisition.state.state not in {"ready", "fetching", "acquired"}:
            raise ReviewedMaterialImportError(
                f"{source_id}: unexpected rights-ready acquisition state {acquisition.state.state}"
            )
        # No local bytes exist in the reviewed Crossref audit.  Deliberately do
        # not begin a fetch or create paper_resource here.
        return "rights_approved_fetch_not_performed"

    def _crossref_fulltext_failed_closed(
        self,
        *,
        source_id: str,
        candidate_id: str,
        case_id: str,
        rights_row: Mapping[str, object],
        fulltext_row: Mapping[str, object],
        manifest_path: Path,
        provenance_urn: str,
    ) -> str:
        request = fulltext_row.get("request")
        rights = fulltext_row.get("rights")
        reading = fulltext_row.get("reading")
        failure = fulltext_row.get("failure")
        if not all(
            isinstance(value, Mapping)
            for value in (request, rights, reading, failure)
        ):
            raise ReviewedMaterialImportError(
                f"{source_id}: rights-conflicted fulltext material is malformed"
            )
        assert isinstance(request, Mapping)
        assert isinstance(rights, Mapping)
        assert isinstance(reading, Mapping)
        assert isinstance(failure, Mapping)
        offers = rights_row.get("official_fulltext_offers")
        approved = [
            offer
            for offer in offers or []
            if isinstance(offer, Mapping)
            and offer.get("acquisition_status") == "available_verified_open_pdf"
            and offer.get("mime_verified_pdf") is True
        ]
        if len(approved) != 1:
            raise ReviewedMaterialImportError(
                f"{source_id}: failed-closed GET has no unique pre-GET reviewed offer"
            )
        offer_url = str(request.get("request_url") or "")
        if offer_url != str(approved[0].get("url") or ""):
            raise ReviewedMaterialImportError(
                f"{source_id}: failed-closed GET URL differs from reviewed offer"
            )
        offer_id = self._offer_id(case_id, offer_url)
        pdf = _verified_artifact(
            _resolve_artifact(manifest_path.parent, request.get("body_path")),
            expected_sha256=str(request.get("sha256") or ""),
            expected_bytes=int(request.get("bytes") or -1),
        )
        request_hash = _sha256(
            canonical_json(
                {
                    "method": request.get("method"),
                    "request_url": request.get("request_url"),
                    "final_url": request.get("final_url"),
                    "sha256": request.get("sha256"),
                    "request_receipt_sha256": request.get("request_receipt_sha256"),
                }
            ).encode("utf-8")
        )
        legal_basis = str(reading.get("reason") or "Post-GET rights conflict.")
        fetch = self.repository.record_fetch_attempt(
            FetchAttemptInput(
                requested_url=offer_url,
                redirect_chain=tuple(
                    str(value) for value in request.get("redirects", []) or []
                ),
                final_url=str(request.get("final_url") or offer_url),
                http_status=int(request.get("http_status") or 0),
                response_mime=str(request.get("content_type") or "application/pdf").split(
                    ";", 1
                )[0],
                response_bytes=len(pdf),
                response_sha256=_sha256(pdf),
                request_identity_hash=request_hash,
                rights_status="license_blocked",
                legal_basis=legal_basis,
                result_status="license_blocked",
                error_class=str(failure.get("code") or "embedded_rights_conflict"),
                error_detail=str(failure.get("remediation") or legal_basis),
            ),
            paper_id=None,
            candidate_id=candidate_id,
            attempt_key=f"reviewed-crossref-blocked-pdf:{source_id}:{_sha256(pdf)}",
        )
        assessment = self.expansion.record_rights_assessment(
            offer_id,
            RightsAssessmentProposal(
                decision="blocked",
                rights_status="license_blocked",
                authority_kind="human_review",
                policy_version=IMPORT_POLICY_VERSION,
                legal_basis=legal_basis,
                evidence={
                    "pre_get_license_url": rights.get("license_url"),
                    "post_get_rights_status": rights.get("rights_status"),
                    "redistribution_authorized": rights.get(
                        "redistribution_authorized"
                    ),
                    "embedded_rights_review": rights.get(
                        "post_get_embedded_rights_review"
                    ),
                    "fetch_attempt_id": fetch.fetch_attempt_id,
                    "pdf_sha256": _sha256(pdf),
                    "fact_boundary": (
                        "transport succeeded, but the exact downloaded bytes failed "
                        "post-GET rights reconciliation and cannot become a resource"
                    ),
                },
            ),
            idempotency_key=f"reviewed-crossref-post-get-rights:{source_id}",
            provenance_urn=f"{provenance_urn}:post-get-rights:{source_id}",
        )
        acquisition = self.expansion.open_acquisition_case(
            offer_id,
            assessment.rights_assessment_id,
            provenance_urn=f"{provenance_urn}:blocked-acquisition:{source_id}",
        )
        if acquisition.state.state != "blocked":
            raise ReviewedMaterialImportError(
                f"{source_id}: post-GET rights conflict did not enter blocked acquisition state"
            )
        return "fulltext_verified_but_license_conflict_blocked"

    def _process_arxiv_resource(
        self,
        *,
        source_id: str,
        candidate_id: str,
        case_id: str,
        material: Mapping[str, object],
        materials_root: Path,
        provenance_urn: str,
    ) -> tuple[str | None, str | None, str]:
        official = material.get("official_metadata")
        rights = material.get("rights")
        if not isinstance(official, Mapping) or not isinstance(rights, Mapping):
            raise ReviewedMaterialImportError(f"{source_id}: material lacks metadata/rights")
        official_urls = official.get("official_urls")
        if not isinstance(official_urls, Mapping):
            raise ReviewedMaterialImportError(f"{source_id}: material lacks official URLs")
        pdf_url = str(official_urls.get("pdf") or "")
        offer_id = self._offer_id(case_id, pdf_url)
        automatic = self.expansion.assess_offer(
            offer_id,
            ConservativeRightsPolicy(),
            idempotency_key=f"reviewed-arxiv-rights-auto:{source_id}",
            provenance_urn=f"{provenance_urn}:rights-auto:{source_id}",
        )
        rights_status = str(rights.get("rights_status") or "")
        if rights_status in {"repository_distribution_only", "verified_open_license"}:
            decision = "approved_for_local_storage"
            normalized_rights_status = rights_status
            resource_status = "verified_local_resource"
        elif rights_status in {
            "official_repository_access_with_embedded_no_redistribution_notice",
            "official_repository_access_with_embedded_limited_reproduction_notice",
            "official_repository_access_with_embedded_all_rights_reserved_notice",
        }:
            decision = "blocked"
            normalized_rights_status = "license_blocked"
            resource_status = "license_blocked_no_local_resource"
        elif rights_status == "official_repository_access_no_per_paper_license_exposed":
            decision = "metadata_only"
            normalized_rights_status = "unknown"
            resource_status = "metadata_only_no_storage_rights"
        else:
            raise ReviewedMaterialImportError(
                f"{source_id}: unsupported reviewed rights status {rights_status!r}"
            )
        reviewed = self.expansion.record_rights_assessment(
            offer_id,
            RightsAssessmentProposal(
                decision=decision,
                rights_status=normalized_rights_status,
                authority_kind="human_review",
                policy_version=IMPORT_POLICY_VERSION,
                legal_basis=str(rights.get("interpretation") or "Reviewed arXiv repository rights."),
                evidence={
                    "paper_license_urls": rights.get("paper_license_urls") or [],
                    "policy_url": rights.get("general_policy_url"),
                    "license_class": rights.get("license_class"),
                    "license_evidence": rights.get("license_evidence") or [],
                    "attribution_requirements": rights.get(
                        "attribution_requirements"
                    )
                    or [],
                    "embedded_pdf_rights_notices": rights.get(
                        "embedded_pdf_rights_notices"
                    )
                    or [],
                    "acquisition_decision": rights.get("acquisition_decision"),
                    "serving_decision": rights.get("serving_decision"),
                    "restriction_controls_fail_closed": rights.get(
                        "restriction_controls_fail_closed"
                    ),
                    "redistribution_authorized_by_this_audit": rights.get(
                        "redistribution_authorized_by_this_audit"
                    ),
                    "fact_boundary": "local evidence storage does not expand redistribution rights",
                },
            ),
            idempotency_key=f"reviewed-arxiv-rights:{source_id}",
            provenance_urn=f"{provenance_urn}:rights:{source_id}",
            supersedes_assessment_id=automatic.rights_assessment_id,
        )
        acquisition: AcquisitionCaseRecord = self.expansion.open_acquisition_case(
            offer_id,
            reviewed.rights_assessment_id,
            provenance_urn=f"{provenance_urn}:acquisition:{source_id}",
        )
        if decision != "approved_for_local_storage":
            if acquisition.state.state != "blocked":
                raise ReviewedMaterialImportError(
                    f"{source_id}: non-storable resource did not enter blocked state"
                )
            return acquisition.acquisition_case_id, None, resource_status
        if acquisition.state.state == "acquired":
            with evidence_connection(self.settings) as connection:
                row = connection.execute(
                    """
                    SELECT resource_id FROM evidence_acquisition_event
                    WHERE acquisition_case_id=? AND event_kind='fetch_succeeded'
                    ORDER BY occurred_at DESC LIMIT 1
                    """,
                    (acquisition.acquisition_case_id,),
                ).fetchone()
            if row is None:
                raise ReviewedMaterialImportError(
                    f"{source_id}: acquired state lacks resource event"
                )
            return (
                acquisition.acquisition_case_id,
                str(row["resource_id"]),
                "verified_local_resource",
            )
        state = acquisition.state
        if state.state == "ready":
            state, _ = self.expansion.begin_acquisition(
                acquisition.acquisition_case_id,
                expected_revision=state.revision,
                idempotency_key=f"reviewed-arxiv-fetch-start:{source_id}",
            )
        if state.state != "fetching":
            raise ReviewedMaterialImportError(
                f"{source_id}: acquisition cannot consume reviewed PDF from {state.state}"
            )
        request, pdf = _request_artifact(materials_root, material, "pdf")
        if not pdf.startswith(b"%PDF-"):
            raise ReviewedMaterialImportError(f"{source_id}: reviewed PDF magic is invalid")
        request_hash = _sha256(
            canonical_json(
                {
                    "method": request.get("method"),
                    "request_url": request.get("request_url"),
                    "final_url": request.get("final_url"),
                    "sha256": request.get("sha256"),
                }
            ).encode("utf-8")
        )
        fetch = self.repository.record_fetch_attempt(
            FetchAttemptInput(
                requested_url=str(request["request_url"]),
                redirect_chain=tuple(str(value) for value in request.get("redirects", []) or []),
                final_url=str(request["final_url"]),
                http_status=int(request["http_status"]),
                response_mime="application/pdf",
                response_bytes=len(pdf),
                response_sha256=_sha256(pdf),
                request_identity_hash=request_hash,
                rights_status=normalized_rights_status,
                legal_basis=str(rights.get("interpretation") or "Reviewed arXiv rights."),
                result_status="succeeded",
            ),
            paper_id=None,
            candidate_id=candidate_id,
            attempt_key=f"reviewed-arxiv-pdf:{source_id}:{_sha256(pdf)}",
        )
        staged = self.resources.put_pdf(pdf)
        resource_id, _ = self.repository.register_resource(
            paper_id=None,
            candidate_id=candidate_id,
            fetch_attempt_id=fetch.fetch_attempt_id,
            content_sha256=staged.content_sha256,
            size=staged.bytes,
            relative_path=staged.relative_path,
            rights_status=normalized_rights_status,
        )
        self.expansion.complete_acquisition(
            acquisition.acquisition_case_id,
            expected_revision=state.revision,
            fetch_attempt_id=fetch.fetch_attempt_id,
            resource_id=resource_id,
            idempotency_key=f"reviewed-arxiv-fetch-complete:{source_id}",
        )
        return acquisition.acquisition_case_id, resource_id, "verified_local_resource"

    def _import_reviewed_open_pdfs(
        self,
        *,
        sources: ReviewedMaterialSources,
        plan: Mapping[str, object],
        provenance_urn: str,
    ) -> tuple[ImportedOpenPdf, ...]:
        review_plan = plan.get("open_pdf_review")
        if review_plan is None:
            return ()
        if not isinstance(review_plan, Mapping) or sources.open_pdf_review_summary is None:
            raise ReviewedMaterialImportError("open PDF plan/source binding is incomplete")
        verified_plan, _ = _open_pdf_review_bundle(
            sources.open_pdf_review_summary
        )
        if verified_plan != review_plan:
            raise ReviewedMaterialImportError(
                "open PDF review changed between planning and import"
            )
        projection = review_plan.get("allowed_projection")
        if not isinstance(projection, list):
            raise ReviewedMaterialImportError("open PDF allowed projection is missing")
        package_root = sources.open_pdf_review_summary.resolve(strict=True).parent
        imported: list[ImportedOpenPdf] = []
        for item in projection:
            if not isinstance(item, Mapping):
                raise ReviewedMaterialImportError("open PDF projection row is malformed")
            source_id = str(item["source_candidate_id"])
            paper_id = str(item["paper_id"])
            scheme = str(item["identifier_scheme"])
            identifier = str(item["normalized_identifier"])
            with evidence_connection(self.settings) as connection:
                identity = connection.execute(
                    """
                    SELECT catalog.title,identifier.normalized_value,
                           receipt.source_candidate_id
                    FROM paper
                    JOIN paper_catalog_projection AS catalog USING(paper_id)
                    JOIN identifier_assignment_projection AS identifier USING(paper_id)
                    JOIN evidence_canonicalization_receipt AS receipt USING(paper_id)
                    WHERE paper.paper_id=? AND identifier.scheme=?
                    """,
                    (paper_id, scheme),
                ).fetchone()
            if identity is None or (
                str(identity["title"]),
                str(identity["normalized_value"]),
                str(identity["source_candidate_id"]),
            ) != (str(item["title"]), identifier, source_id):
                raise ReviewedMaterialImportError(
                    f"{source_id}: replay identity differs from reviewed open PDF"
                )
            pdf_path = (
                package_root / Path(str(item["relative_path"]))
            ).resolve(strict=True)
            if not pdf_path.is_relative_to(package_root):
                raise ReviewedMaterialImportError(
                    f"{source_id}: reviewed PDF escapes its package"
                )
            pdf = _verified_artifact(
                pdf_path,
                expected_sha256=str(item["content_sha256"]),
                expected_bytes=int(item["bytes"]),
            )
            if not pdf.startswith(b"%PDF-"):
                raise ReviewedMaterialImportError(
                    f"{source_id}: reviewed local resource is not a PDF"
                )
            request_identity_hash = _sha256(
                canonical_json(
                    {
                        "schema_version": "qrh-reviewed-open-pdf-fetch/v1",
                        "source_candidate_id": source_id,
                        "paper_id": paper_id,
                        "source_url": item["source_url"],
                        "final_url": item["final_url"],
                        "content_sha256": item["content_sha256"],
                        "bytes": item["bytes"],
                        "license": item["license"],
                        "license_url": item["license_url"],
                        "rights_evidence_url": item["rights_evidence_url"],
                        "rights_evidence_sha256": item[
                            "rights_evidence_sha256"
                        ],
                        "final_review_sha256": review_plan[
                            "final_review_sha256"
                        ],
                        "independent_verification_sha256": review_plan[
                            "independent_verification_sha256"
                        ],
                    }
                ).encode("utf-8")
            )
            legal_basis = (
                f"独立开放 PDF 复核通过：{item['license']}（{item['license_url']}）；"
                f"权利证据 {item['rights_evidence_url']}，artifact sha256 "
                f"{item['rights_evidence_sha256']}；final review sha256 "
                f"{review_plan['final_review_sha256']}。"
            )
            fetch = self.repository.record_fetch_attempt(
                FetchAttemptInput(
                    requested_url=str(item["source_url"]),
                    redirect_chain=(),
                    final_url=str(item["final_url"]),
                    http_status=200,
                    response_mime="application/pdf",
                    response_bytes=len(pdf),
                    response_sha256=_sha256(pdf),
                    request_identity_hash=request_identity_hash,
                    rights_status="verified_open_license",
                    legal_basis=legal_basis,
                    result_status="succeeded",
                ),
                paper_id=paper_id,
                candidate_id=None,
                attempt_key=(
                    f"reviewed-open-pdf:{source_id}:{_sha256(pdf)}:"
                    f"{review_plan['final_review_sha256']}"
                ),
                subject_urn=f"qrh:evidence:paper:{paper_id}",
            )
            staged = self.resources.put_pdf(pdf)
            resource_id, _ = self.repository.register_resource(
                paper_id=paper_id,
                fetch_attempt_id=fetch.fetch_attempt_id,
                content_sha256=staged.content_sha256,
                size=staged.bytes,
                relative_path=staged.relative_path,
                rights_status="verified_open_license",
            )
            self.repository.refresh_catalog_resources(paper_id)
            imported.append(
                ImportedOpenPdf(
                    source_candidate_id=source_id,
                    paper_id=paper_id,
                    normalized_identifier=identifier,
                    fetch_attempt_id=fetch.fetch_attempt_id,
                    resource_id=resource_id,
                    content_sha256=staged.content_sha256,
                    bytes=staged.bytes,
                    rights_status="verified_open_license",
                )
            )
        if len(imported) != int(review_plan["allowed_count"]):
            raise ReviewedMaterialImportError(
                "open PDF import count differs from its independent closed set"
            )
        return tuple(imported)

    def apply(
        self,
        sources: ReviewedMaterialSources,
        *,
        review_id: str,
        reviewed_by: str,
        reviewed_at: str,
        provenance_urn: str,
        include_source_candidates: frozenset[str] | None = None,
    ) -> ReviewedMaterialImportResult:
        plan = self.static_plan(
            sources, include_source_candidates=include_source_candidates
        )
        # All frozen-input, independent-verdict, rights and receipt validation
        # must finish before migrations create or mutate the selected runtime.
        self.repository.initialize()
        overrides = _reconciliation_overrides(sources.reconciliation_overrides)
        crossref_rows = _crossref_rows(sources.crossref_decisions)
        identity_verdicts = _crossref_identity_verdict_rows(
            sources.crossref_identity_verdicts,
            decision_rows=crossref_rows,
        )
        rights_by_source = _crossref_rights_rows(
            sources.crossref_rights_manifest,
            decision_rows=crossref_rows,
        )
        for source_id, row in crossref_rows.items():
            _validate_crossref_rights_row(
                row,
                rights_by_source.get(source_id),
                identity_verdicts.get(source_id),
            )
        fulltext_by_source = _crossref_fulltext_rows(
            sources.crossref_fulltext_manifest,
            decision_rows=crossref_rows,
            rights_rows=rights_by_source,
        )
        crossref_results: list[ImportedIdentity] = []
        for source_id, row in sorted(crossref_rows.items()):
            if include_source_candidates is not None and source_id not in include_source_candidates:
                continue
            if not _crossref_reconciliation_allows(source_id, overrides):
                continue
            if (
                identity_verdicts
                and identity_verdicts[source_id].get("identity_verdict") != "PASS"
            ):
                continue
            doi = normalize_identifier("doi", str(row["selected_doi"]))
            body, metadata = _crossref_body(row)
            adapter = CrossrefAdapter()
            query = ResolutionQuery(
                identifiers=(
                    StrongIdentifierQuery(
                        scheme="doi",
                        raw_value=doi,
                        source_provenance_urn=f"{provenance_urn}:crossref-review:{source_id}",
                    ),
                )
            )
            planned = adapter.plan(query)[0]
            endpoint = str(metadata.get("endpoint") or "")
            if endpoint != planned.url:
                raise ReviewedMaterialImportError(
                    f"{source_id}: Crossref cached endpoint differs from frozen request: {endpoint} != {planned.url}"
                )
            response = ProviderHttpResponse(
                request_url=endpoint,
                final_url=endpoint,
                status_code=int(metadata["http_status"]),
                headers={
                    "Content-Type": str(metadata.get("content_type") or "application/json"),
                    "Content-Length": str(len(body)),
                },
                body=body,
            )
            candidate_id, case_id, decision_id, _ = self._import_identity(
                source_candidate_id=source_id,
                paper_source_candidate_id=source_id,
                scheme="doi",
                raw_identifier=doi,
                adapter=adapter,
                response=response,
                rationale=str(row.get("decision_reason") or "Reviewed exact DOI identity."),
                provenance_urn=f"{provenance_urn}:crossref:{source_id}",
            )
            fulltext = fulltext_by_source.get(source_id)
            if fulltext is not None:
                if sources.crossref_fulltext_manifest is None:
                    raise AssertionError("fulltext row loaded without its manifest path")
                resource_status = self._crossref_fulltext_failed_closed(
                    source_id=source_id,
                    candidate_id=candidate_id,
                    case_id=case_id,
                    rights_row=rights_by_source[source_id],
                    fulltext_row=fulltext,
                    manifest_path=sources.crossref_fulltext_manifest,
                    provenance_urn=provenance_urn,
                )
            else:
                resource_status = self._crossref_rights_ready(
                    source_id=source_id,
                    case_id=case_id,
                    rights_row=rights_by_source.get(source_id),
                    provenance_urn=provenance_urn,
                )
            crossref_results.append(
                ImportedIdentity(
                    source_candidate_id=source_id,
                    paper_source_candidate_id=source_id,
                    provider="crossref",
                    identifier_scheme="doi",
                    normalized_identifier=doi,
                    resolution_case_id=case_id,
                    identity_decision_id=decision_id,
                    resource_status=resource_status,
                )
            )

        bundle = _arxiv_reviewed_bundle(sources)
        materials = bundle.materials
        reading_by_source = {
            source_id: row for source_id, (row, _) in bundle.readings.items()
        }
        if bundle.method_origin_inputs_path is not None:
            derivations = method_origin_inputs_from_reviewed_manifest(
                bundle.method_origin_inputs_path,
                include_source_candidates=include_source_candidates,
            )
        else:
            derivations = method_origin_inputs_from_arxiv_readings(
                bundle.reading_paths,
                provenance_urn=f"{provenance_urn}:method-origin",
                include_source_candidates=include_source_candidates,
            )
        if derivations:
            self.canonicalization.prepare_method_origin_candidates(derivations)

        resolution_seed_sha256 = (
            _sha256(bundle.resolution_seed_path.read_bytes())
            if bundle.resolution_seed_path is not None
            else None
        )
        arxiv_results: list[ImportedIdentity] = []
        for source_id, (materials_root, material) in sorted(materials.items()):
            reading = reading_by_source[source_id]
            if not _include_arxiv_source(
                source_id, reading, include_source_candidates
            ):
                continue
            relation = reading["archive_relation"]
            paper_source_id = str(relation["paper_source_candidate_id"])
            resolution_seed_row = bundle.resolution_seed.get(paper_source_id)
            arxiv_id = normalize_identifier(
                "arxiv",
                str(
                    resolution_seed_row["arxiv_id"]
                    if resolution_seed_row is not None
                    else reading["arxiv_id"]
                ),
            )
            resolution_provenance = (
                f":resolution-seed:sha256:{resolution_seed_sha256}"
                if resolution_seed_sha256 is not None
                else ""
            )
            atom_request, atom = _request_artifact(materials_root, material, "atom")
            adapter = ArxivAdapter()
            query = ResolutionQuery(
                identifiers=(
                    StrongIdentifierQuery(
                        scheme="arxiv",
                        raw_value=arxiv_id,
                        source_provenance_urn=(
                            f"{provenance_urn}:arxiv-review:{source_id}"
                            f"{resolution_provenance}"
                        ),
                    ),
                )
            )
            planned = adapter.plan(query)[0]
            if str(atom_request.get("request_url") or "") != planned.url:
                raise ReviewedMaterialImportError(
                    f"{source_id}: arXiv cached Atom request differs from frozen exact request"
                )
            response = ProviderHttpResponse(
                request_url=planned.url,
                final_url=str(atom_request["final_url"]),
                redirect_chain=tuple(
                    str(value) for value in atom_request.get("redirects", []) or []
                ),
                status_code=int(atom_request["http_status"]),
                headers={
                    "Content-Type": str(
                        atom_request.get("content_type") or "application/atom+xml"
                    ),
                    "Content-Length": str(len(atom)),
                },
                body=atom,
            )
            candidate_id, case_id, decision_id, _ = self._import_identity(
                source_candidate_id=source_id,
                paper_source_candidate_id=paper_source_id,
                scheme="arxiv",
                raw_identifier=arxiv_id,
                adapter=adapter,
                response=response,
                rationale=(
                    "Reviewed official arXiv identifier, Atom metadata, abstract page, "
                    "and PDF identity checks agree."
                ),
                provenance_urn=f"{provenance_urn}:arxiv:{source_id}",
            )
            _, resource_id, resource_status = self._process_arxiv_resource(
                source_id=source_id,
                candidate_id=candidate_id,
                case_id=case_id,
                material=material,
                materials_root=materials_root,
                provenance_urn=provenance_urn,
            )
            arxiv_results.append(
                ImportedIdentity(
                    source_candidate_id=source_id,
                    paper_source_candidate_id=paper_source_id,
                    provider="arxiv",
                    identifier_scheme="arxiv",
                    normalized_identifier=arxiv_id,
                    resolution_case_id=case_id,
                    identity_decision_id=decision_id,
                    resource_status=resource_status,
                    resource_id=resource_id,
                )
            )

        crossref_count = 0
        if crossref_results:
            manifest = build_crossref_reviewed_manifest(
                self.settings,
                sources.crossref_decisions,
                review_id=f"{review_id}:crossref",
                reviewed_by=reviewed_by,
                reviewed_at=reviewed_at,
                idempotency_key=f"{review_id}:crossref",
                provenance_urn=f"{provenance_urn}:crossref-canonicalization",
                reconciliation_overrides=overrides,
                identity_verdicts=identity_verdicts,
                include_source_candidates=include_source_candidates,
            )
            crossref_count = len(self.canonicalization.apply(manifest).items)

        arxiv_count = 0
        if arxiv_results:
            manifest = build_arxiv_reviewed_manifest(
                self.settings,
                bundle.material_paths,
                bundle.reading_paths,
                review_id=f"{review_id}:arxiv",
                reviewed_by=reviewed_by,
                reviewed_at=reviewed_at,
                idempotency_key=f"{review_id}:arxiv",
                provenance_urn=f"{provenance_urn}:arxiv-canonicalization",
                include_source_candidates=include_source_candidates,
            )
            arxiv_count = len(self.canonicalization.apply(manifest).items)

        open_pdf_resources = self._import_reviewed_open_pdfs(
            sources=sources,
            plan=plan,
            provenance_urn=f"{provenance_urn}:open-pdf-review",
        )

        if len(crossref_results) != int(plan["crossref_eligible"]):
            raise EvidenceExpansionConflict("Crossref plan/apply identity count diverged")
        if len(arxiv_results) != int(plan["arxiv_reviewed"]):
            raise EvidenceExpansionConflict("arXiv plan/apply identity count diverged")
        return ReviewedMaterialImportResult(
            crossref_identities=tuple(crossref_results),
            arxiv_identities=tuple(arxiv_results),
            crossref_canonical_papers=crossref_count,
            arxiv_canonical_papers=arxiv_count,
            method_origin_derivations=len(derivations),
            open_pdf_resources=open_pdf_resources,
        )
