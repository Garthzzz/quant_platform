from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from quant_hub.archive.source_reader import ReadOnlyArchiveSource
from quant_hub.config import Settings

from .contracts import CitationOccurrenceInput, FetchAttemptInput, StrongIdentifierInput
from .export import InventoryExport, export_inventory
from .repository import EvidenceConflict, EvidenceRepository
from .resources import EvidenceResourceStore


class EvidenceFixtureError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FixtureImportResult:
    case_count: int
    paper_count: int
    resource_count: int
    citation_ids: tuple[str, ...]
    inventory: InventoryExport
    counts: dict[str, int]


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceFixtureError(f"invalid UTF-8 JSON fixture: {path}") from error
    if not isinstance(value, dict):
        raise EvidenceFixtureError("fixture root must be an object")
    return value


def _project_path(project_root: Path, value: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise EvidenceFixtureError("fixture path must be a safe project-relative POSIX path")
    target = project_root.joinpath(*pure.parts).resolve(strict=True)
    try:
        target.relative_to(project_root.resolve(strict=True))
    except ValueError as error:
        raise EvidenceFixtureError("fixture path escapes project root") from error
    return target


def import_vertical_fixture(
    settings: Settings,
    manifest_path: Path,
) -> FixtureImportResult:
    """回放五类冻结线索；外部事实只取自显式 provenance manifest。"""

    manifest = _load_json(manifest_path)
    if manifest.get("schema_version") != "qrh-evidence-vertical-slice/v1":
        raise EvidenceFixtureError("unsupported Evidence fixture schema")
    selection_path = _project_path(
        settings.project_root, str(manifest["selection_fixture"])
    )
    selection = _load_json(selection_path)
    selection_cases = {
        str(case["fixture_id"]): case for case in selection.get("cases", [])
    }
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != 5:
        raise EvidenceFixtureError("vertical slice must contain exactly five cases")
    expected_fixture_ids = {str(case["fixture_id"]) for case in cases}
    if set(selection_cases).intersection(expected_fixture_ids) != expected_fixture_ids:
        raise EvidenceFixtureError("selection fixture does not contain every vertical case")

    source_paths = {
        str(selection_cases[str(case["fixture_id"])]["occurrence"]["source_path"])
        for case in cases
    }
    if len(source_paths) != 1:
        raise EvidenceFixtureError("vertical cases must bind one exact Archive document")
    frozen_source_path = source_paths.pop()
    # A source may be renamed without changing a byte.  The legacy occurrence
    # ledger remains frozen, while this explicit override binds the fixture to
    # the current canonical Archive path after re-verifying the same SHA-256.
    canonical_source_path = str(
        manifest.get("canonical_source_path") or frozen_source_path
    )
    snapshot = ReadOnlyArchiveSource(settings.archive_root).snapshot(
        canonical_source_path
    )
    if snapshot.sha256 != manifest["source_document_sha256"]:
        raise EvidenceFixtureError("current Archive bytes differ from frozen fixture identity")

    repository = EvidenceRepository(settings)
    repository.initialize()
    resource_store = EvidenceResourceStore(settings)
    citation_ids: list[str] = []
    paper_count = 0
    resource_count = 0

    for case in cases:
        fixture_id = str(case["fixture_id"])
        selected = selection_cases[fixture_id]
        if (
            selected["candidate_claim"]["candidate_id"] != case["source_candidate_id"]
            or selected["occurrence"]["occurrence_id"] != case["legacy_occurrence_id"]
        ):
            raise EvidenceFixtureError("vertical manifest IDs differ from frozen selection")
        candidate_claim = dict(selected["candidate_claim"])
        clue_provenance = f"qrh:fixture:archive-paper-clues:{case['source_candidate_id']}"
        clue_id, _ = repository.put_clue(
            source_candidate_id=str(case["source_candidate_id"]),
            entity_kind=str(candidate_claim["entity_type"]),
            domain_category=(
                str(candidate_claim["domain_category"])
                if candidate_claim.get("domain_category")
                else None
            ),
            raw_claim=candidate_claim,
            provenance_urn=clue_provenance,
            resolution_status=str(case["clue_resolution_status"]),
        )

        paper_data = case.get("paper")
        external_provenance = (
            str(paper_data["provenance_urn"])
            if isinstance(paper_data, dict)
            else clue_provenance
        )
        raw_year = str(candidate_claim.get("year") or "")
        publication_year = int(raw_year) if raw_year.isdigit() else None
        candidate_id, _ = repository.put_candidate(
            source_candidate_id=str(case["source_candidate_id"]),
            candidate_kind="paper" if paper_data is not None else "non_paper_resource",
            title_claim=(
                str(paper_data["title"])
                if isinstance(paper_data, dict)
                else (str(candidate_claim.get("title")) or None)
            ),
            publication_year=publication_year,
            resolution_status=str(case["candidate_resolution_status"]),
            provenance_urn=external_provenance,
        )
        repository.link_clue_candidate(
            clue_id,
            candidate_id,
            link_kind=("external_resolution" if paper_data is not None else "local_claim"),
            evidence={
                "fixture_id": fixture_id,
                "local_claim_provenance": clue_provenance,
                "external_provenance": external_provenance if paper_data else None,
            },
        )

        paper_id: str | None = None
        fetch_attempt_id: str | None = None
        if isinstance(paper_data, dict):
            identity = paper_data["identity"]
            identity_input = StrongIdentifierInput(
                scheme=identity["scheme"],
                raw_value=identity["value"],
                assertion_status="verified",
                provenance_urn=paper_data["provenance_urn"],
            )
            paper = repository.create_paper(
                f"{identity_input.scheme}:{identity_input.normalized_value}",
                provenance_urn=str(paper_data["provenance_urn"]),
            )
            paper_id = paper.paper_id
            paper_count += 1
            for field_name, value in (
                ("title", paper_data["title"]),
                ("publication_date", paper_data["publication_date"]),
                ("author", paper_data["authors"]),
                ("institution", paper_data["institutions"]),
            ):
                assertion_id, _ = repository.assert_metadata(
                    paper_id=paper_id,
                    candidate_id=candidate_id,
                    field_name=field_name,
                    value=value,
                    assertion_status="verified",
                    source_kind=str(paper_data["metadata_source_kind"]),
                    provenance_urn=str(paper_data["provenance_urn"]),
                )
                repository.select_metadata(
                    paper_id=paper_id,
                    field_name=field_name,
                    assertion_id=assertion_id,
                    provenance_urn=str(paper_data["provenance_urn"]),
                )
            for identifier in paper_data["identifiers"]:
                repository.assert_and_assign_identifier(
                    paper_id,
                    StrongIdentifierInput(
                        scheme=identifier["scheme"],
                        raw_value=identifier["value"],
                        assertion_status="verified",
                        provenance_urn=identifier["provenance_urn"],
                    ),
                    candidate_id=candidate_id,
                )

        fetch_data = case.get("fetch")
        if isinstance(fetch_data, dict):
            request_identity_hash = hashlib.sha256(
                b"qrh-evidence-fixture-fetch-client/v1"
            ).hexdigest()
            attempt = repository.record_fetch_attempt(
                FetchAttemptInput(
                    requested_url=fetch_data["requested_url"],
                    redirect_chain=tuple(fetch_data["redirect_chain"]),
                    final_url=fetch_data["final_url"],
                    http_status=fetch_data["http_status"],
                    response_mime=fetch_data["response_mime"],
                    response_bytes=fetch_data["response_bytes"],
                    response_sha256=fetch_data["response_sha256"],
                    request_identity_hash=request_identity_hash,
                    rights_status=fetch_data["rights_status"],
                    legal_basis=fetch_data["legal_basis"],
                    result_status=fetch_data["result_status"],
                    error_class=fetch_data["error_class"],
                    error_detail=fetch_data["error_detail"],
                ),
                paper_id=paper_id,
                candidate_id=candidate_id,
                attempt_key=fixture_id,
            )
            fetch_attempt_id = attempt.fetch_attempt_id

        resource_data = case.get("resource")
        if isinstance(resource_data, dict):
            if paper_id is None or fetch_attempt_id is None:
                raise EvidenceFixtureError("resource requires a paper and fetch audit")
            pure_resource = PurePosixPath(str(resource_data["fixture_path"]))
            if pure_resource.is_absolute() or any(
                part in {"", ".", ".."} for part in pure_resource.parts
            ):
                raise EvidenceFixtureError("fixture resource path is unsafe")
            resource_source = manifest_path.parent.joinpath(*pure_resource.parts)
            staged = resource_store.put_pdf_from_path(resource_source)
            if (
                staged.content_sha256 != fetch_data["response_sha256"]
                or staged.bytes != fetch_data["response_bytes"]
            ):
                raise EvidenceFixtureError("fixture PDF differs from fetch audit")
            repository.register_resource(
                paper_id=paper_id,
                candidate_id=candidate_id,
                fetch_attempt_id=fetch_attempt_id,
                content_sha256=staged.content_sha256,
                size=staged.bytes,
                relative_path=staged.relative_path,
                rights_status=str(resource_data["rights_status"]),
            )
            resource_count += 1

        if isinstance(paper_data, dict) and paper_id is not None:
            repository.put_bibliography_projection(
                paper_id=paper_id,
                title=str(paper_data["title"]),
                publication_date=str(paper_data["publication_date"]),
                authors=list(paper_data["authors"]),
                institutions=list(paper_data["institutions"]),
                categories=list(paper_data["categories"]),
                core_conclusions=list(paper_data["core_conclusions"]),
                external_links=list(paper_data["external_links"]),
                provenance_urn=str(paper_data["provenance_urn"]),
            )

        occurrence = selected["occurrence"]
        kind = {
            "strong_identifier_arxiv": "strong_identifier",
            "formal_reference_list_occurrence": "formal_reference",
            "method_or_resource_name": "method_or_resource_name",
        }[str(occurrence["occurrence_type"])]
        binding_status = str(case["binding_status"])
        citation = CitationOccurrenceInput(
            legacy_occurrence_id=str(occurrence["occurrence_id"]),
            clue_id=clue_id,
            research_urn=str(manifest["research_urn"]),
            archive_release_urn=str(manifest["archive_release_urn"]),
            document_version_urn=str(manifest["document_version_urn"]),
            source_object_urn=str(selected["b_binding"]["approved_object_urn"]),
            document_sha256=str(occurrence["source_sha256"]),
            source_path=canonical_source_path,
            canonical_path=canonical_source_path,
            locator_claim=f"line:{occurrence['line']}",
            locator_kind="utf8_bytes",
            locator={
                "line": int(occurrence["line"]),
                "byte_start": int(occurrence["byte_start"]),
                "byte_end": int(occurrence["byte_end"]),
            },
            line_start=int(occurrence["line"]),
            line_end=int(occurrence["line"]),
            byte_start=int(occurrence["byte_start"]),
            byte_end=int(occurrence["byte_end"]),
            raw_marker_text=str(occurrence["original_clue"]),
            context_text=str(occurrence["context_line"]),
            occurrence_kind=kind,
            resolution_status=binding_status,
            status_reason=str(case["binding_reason"]),
            raw_occurrence_type=str(occurrence["occurrence_type"]),
            candidate_link_method=str(occurrence["candidate_link_method"]),
            evidence_strength=str(occurrence["evidence_strength"]),
            identifier_claim=str(occurrence.get("identifier") or ""),
            ledger_payload={
                **dict(occurrence),
                "canonical_source_path": canonical_source_path,
                "frozen_source_path": frozen_source_path,
            },
        )
        repository.add_citation(citation, snapshot.content)
        repository.bind_citation(
            citation.legacy_occurrence_id,
            paper_id=paper_id if binding_status == "resolved" else None,
            binding_status=binding_status,
            rationale=str(case["binding_reason"]),
            provenance_urn=f"qrh:fixture-binding:{fixture_id}",
        )
        if binding_status == "resolved":
            assert paper_id is not None
            repository.add_research_relation(
                research_urn=str(manifest["research_urn"]),
                document_version_urn=str(manifest["document_version_urn"]),
                ledger_entry_id=citation.legacy_occurrence_id,
                citation_id=citation.citation_id,
                paper_id=paper_id,
                relation_kind="formal_reference",
                provenance_urn=f"qrh:fixture-binding:{fixture_id}",
            )
        citation_ids.append(citation.citation_id)

    inventory = export_inventory(settings)
    counts = repository.counts()
    if counts["paper_clue"] != 5 or counts["citation_occurrence"] != 5:
        raise EvidenceConflict("vertical replay did not produce the exact five-case boundary")
    if counts["paper"] != 4 or counts["paper_resource"] != 2:
        raise EvidenceConflict("vertical replay paper/resource disposition differs from fixture")
    return FixtureImportResult(
        case_count=5,
        paper_count=paper_count,
        resource_count=resource_count,
        citation_ids=tuple(citation_ids),
        inventory=inventory,
        counts=counts,
    )
