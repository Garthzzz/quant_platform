from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from quant_hub.config import Settings, ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.platform.db import immediate_transaction, utc_now

from .database import evidence_connection
from .ids import stable_evidence_id
from .repository import EvidenceConflict, EvidenceRepository


INVENTORY_FORMAT_VERSION = "qrh-research-paper-inventory/v1"
CANDIDATE_INVENTORY_FORMAT_VERSION = "qrh-research-paper-candidate-inventory/v1"
INVENTORY_HEADER = (
    "research_urn",
    "document_version_urn",
    "byte_start",
    "candidate_id",
    "citation_id",
    "resolution_status",
    "paper_urn",
    "raw_claim_json",
)
CANDIDATE_INVENTORY_HEADER = (
    "source_candidate_id",
    "clue_id",
    "entity_kind",
    "domain_category",
    "research_urns",
    "source_locators",
    "citation_ledger_count",
    "clue_resolution_status",
    "candidate_resolution_status",
    "identity_reason",
    "paper_id",
    "paper_urn",
    "acquisition_status",
    "acquisition_reason",
    "fetch_attempts",
    "resource_ids",
    "local_resource_links",
    "reading_status",
    "reading_reason",
    "reading_run_ids",
    "raw_claim_json",
)


@dataclass(frozen=True, slots=True)
class InventoryExport:
    export_id: str
    source_snapshot_hash: str
    content_sha256: str
    bytes: int
    relative_path: str
    created: bool


def _json_cell(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def inventory_bytes(settings: Settings) -> bytes:
    """生成无时间字段、顺序固定的 UTF-8/LF 清单。"""

    with evidence_connection(settings) as connection:
        rows = connection.execute(
            """
            SELECT ledger.research_urn,ledger.document_version_urn,
                   COALESCE(occurrence.byte_start,0) AS byte_start,
                   COALESCE(clue.source_candidate_id,'') AS source_candidate_id,
                   occurrence.citation_id,binding.binding_status,paper.canonical_urn,
                   COALESCE(clue.raw_claim_json,ledger.raw_payload_json) AS raw_claim_json
            FROM citation_ledger_entry AS ledger
            JOIN citation_occurrence AS occurrence USING(citation_id)
            LEFT JOIN paper_clue AS clue USING(clue_id)
            LEFT JOIN citation_binding_projection AS current
              ON current.ledger_entry_id=ledger.ledger_entry_id
            LEFT JOIN citation_binding AS binding
              ON binding.binding_id=current.binding_id
            LEFT JOIN paper ON paper.paper_id=binding.paper_id
            ORDER BY ledger.research_urn,ledger.document_version_urn,
                     COALESCE(occurrence.byte_start,0),COALESCE(clue.source_candidate_id,'')
            """
        ).fetchall()
        conservation = [
            (
                str(row["locator_kind"]),
                int(row["ledger_count"]),
                int(row["occurrence_count"]),
            )
            for row in connection.execute(
                """
                SELECT occurrence.locator_kind,count(*) AS ledger_count,
                       count(DISTINCT occurrence.citation_id) AS occurrence_count
                FROM citation_ledger_entry AS ledger
                JOIN citation_occurrence AS occurrence USING(citation_id)
                GROUP BY occurrence.locator_kind ORDER BY occurrence.locator_kind
                """
            )
        ]
    ledger_count = len(rows)
    occurrence_count = sum(item[2] for item in conservation)
    conservation_text = ";".join(
        f"{kind}:{entries}->{occurrences}"
        for kind, entries, occurrences in conservation
    )
    lines = [
        f"# format_version={INVENTORY_FORMAT_VERSION}",
        f"# conservation=ledger_entries:{ledger_count};citation_occurrences:{occurrence_count};"
        "each_ledger_exactly_one_occurrence;each_occurrence_at_least_one_ledger",
        f"# locator_counts={conservation_text}",
        "# dedup_key.utf8_bytes=document_sha256+byte_start+byte_end+raw_marker_sha256",
        "# dedup_key.source_only=document_sha256+locator_kind+source_path+locator+raw_marker_sha256",
        "# alias_policy=source-only locators retain path semantics; cross-path alias collapse is rejected",
        "\t".join(INVENTORY_HEADER),
    ]
    for row in rows:
        cells = (
            _json_cell(str(row["research_urn"])),
            _json_cell(str(row["document_version_urn"])),
            str(int(row["byte_start"])),
            _json_cell(str(row["source_candidate_id"])),
            _json_cell(str(row["citation_id"])),
            _json_cell(
                str(row["binding_status"])
                if row["binding_status"] is not None
                else "unbound"
            ),
            _json_cell(
                str(row["canonical_urn"]) if row["canonical_urn"] is not None else None
            ),
            _json_cell(json.loads(str(row["raw_claim_json"]))),
        )
        lines.append("\t".join(cells))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _identity_reason(clue_status: str) -> str:
    return {
        "externally_verified": "official_arxiv_strong_identifier_verified",
        "resolution_pending": "crossref_candidates_not_selected_no_strong_identifier",
        "unresolved": "no_verified_strong_identifier",
        "conflicted": "local_identity_claim_conflict_requires_resolution",
        "rejected_non_paper": "not_applicable_method_or_resource_clue",
    }[clue_status]


def candidate_inventory_bytes(settings: Settings) -> bytes:
    """生成一候选一行、包含发现到读取全状态的可审计 TXT。"""

    with evidence_connection(settings) as connection:
        base_rows = connection.execute(
            """
            SELECT clue.source_candidate_id,clue.clue_id,clue.entity_kind,
                   clue.domain_category,clue.resolution_status AS clue_status,
                   candidate.resolution_status AS candidate_status,
                   clue.raw_claim_json,identifier.paper_id,paper.canonical_urn
            FROM paper_clue AS clue
            JOIN paper_clue_candidate AS local_link
              ON local_link.clue_id=clue.clue_id AND local_link.link_kind='local_claim'
            JOIN paper_candidate AS candidate USING(candidate_id)
            LEFT JOIN paper_identifier_assertion AS identifier
              ON identifier.candidate_id=candidate.candidate_id
             AND identifier.assertion_status='verified'
            LEFT JOIN paper USING(paper_id)
            ORDER BY clue.source_candidate_id
            """
        ).fetchall()
        locator_rows = connection.execute(
            """
            SELECT clue.source_candidate_id,ledger.ledger_entry_id,
                   ledger.research_urn,ledger.document_version_urn,
                   ledger.source_path,ledger.locator_claim,ledger.occurrence_type,
                   ledger.entry_status,ledger.entry_reason,ledger.citation_id
            FROM citation_ledger_entry AS ledger
            JOIN paper_clue AS clue USING(clue_id)
            ORDER BY clue.source_candidate_id,ledger.research_urn,
                     ledger.document_version_urn,ledger.source_path,
                     ledger.locator_claim,ledger.ledger_entry_id
            """
        ).fetchall()
        fetch_rows = connection.execute(
            """
            SELECT clue.source_candidate_id,fetch.fetch_attempt_id,
                   fetch.result_status,fetch.rights_status,fetch.error_class,
                   fetch.http_status
            FROM fetch_attempt AS fetch
            JOIN paper_clue_candidate AS local_link
              ON local_link.candidate_id=fetch.candidate_id
             AND local_link.link_kind='local_claim'
            JOIN paper_clue AS clue USING(clue_id)
            ORDER BY clue.source_candidate_id,fetch.fetch_attempt_id
            """
        ).fetchall()
        resource_rows = connection.execute(
            """
            SELECT clue.source_candidate_id,resource.resource_id,
                   resource.verification_status,resource.rights_status
            FROM paper_resource AS resource
            JOIN paper_clue_candidate AS local_link
              ON local_link.candidate_id=resource.candidate_id
             AND local_link.link_kind='local_claim'
            JOIN paper_clue AS clue USING(clue_id)
            ORDER BY clue.source_candidate_id,resource.resource_id
            """
        ).fetchall()
        reading_rows = connection.execute(
            """
            SELECT clue.source_candidate_id,run.reading_run_id,
                   run.attempt_number,run.result_status,run.failure_json
            FROM paper_reading_run AS run
            JOIN paper_reading_task AS task USING(reading_task_id)
            JOIN paper_identifier_assertion AS identifier
              ON identifier.paper_id=task.paper_id AND identifier.scheme='arxiv'
            JOIN paper_clue_candidate AS local_link
              ON local_link.candidate_id=identifier.candidate_id
             AND local_link.link_kind='local_claim'
            JOIN paper_clue AS clue USING(clue_id)
            ORDER BY clue.source_candidate_id,run.attempt_number,run.reading_run_id
            """
        ).fetchall()

    if len({str(row["source_candidate_id"]) for row in base_rows}) != len(base_rows):
        raise EvidenceConflict("candidate inventory requires a unique candidate set")

    locators: dict[str, list[dict[str, object]]] = {}
    fetches: dict[str, list[dict[str, object]]] = {}
    resources: dict[str, list[dict[str, object]]] = {}
    readings: dict[str, list[dict[str, object]]] = {}
    for row in locator_rows:
        locators.setdefault(str(row["source_candidate_id"]), []).append(
            {
                "ledger_entry_id": str(row["ledger_entry_id"]),
                "research_urn": str(row["research_urn"]),
                "document_version_urn": str(row["document_version_urn"]),
                "source_path": str(row["source_path"]),
                "locator_claim": str(row["locator_claim"]),
                "occurrence_type": str(row["occurrence_type"]),
                "entry_status": str(row["entry_status"]),
                "entry_reason": str(row["entry_reason"]),
                "citation_id": str(row["citation_id"]),
            }
        )
    for row in fetch_rows:
        fetches.setdefault(str(row["source_candidate_id"]), []).append(
            {
                "fetch_attempt_id": str(row["fetch_attempt_id"]),
                "result_status": str(row["result_status"]),
                "rights_status": str(row["rights_status"]),
                "error_class": str(row["error_class"]) if row["error_class"] else None,
                "http_status": int(row["http_status"]) if row["http_status"] else None,
            }
        )
    for row in resource_rows:
        resources.setdefault(str(row["source_candidate_id"]), []).append(
            {
                "resource_id": str(row["resource_id"]),
                "verification_status": str(row["verification_status"]),
                "rights_status": str(row["rights_status"]),
            }
        )
    for row in reading_rows:
        readings.setdefault(str(row["source_candidate_id"]), []).append(
            {
                "reading_run_id": str(row["reading_run_id"]),
                "attempt_number": int(row["attempt_number"]),
                "result_status": str(row["result_status"]),
                "failure": json.loads(str(row["failure_json"]))
                if row["failure_json"] is not None
                else None,
            }
        )

    lines = [
        f"# format_version={CANDIDATE_INVENTORY_FORMAT_VERSION}",
        (
            "# contract=one_candidate_per_data_line;"
            f"{len(base_rows)}_data_lines;status_and_reason_are_explicit"
        ),
        "\t".join(CANDIDATE_INVENTORY_HEADER),
    ]
    for row in base_rows:
        source_id = str(row["source_candidate_id"])
        candidate_locators = locators.get(source_id, [])
        candidate_fetches = fetches.get(source_id, [])
        candidate_resources = resources.get(source_id, [])
        candidate_readings = readings.get(source_id, [])
        research_urns = sorted(
            {str(item["research_urn"]) for item in candidate_locators}
        )
        if candidate_resources:
            acquisition_status = "acquired_verified"
            acquisition_reason = "verified_local_pdf_available"
        elif candidate_fetches:
            acquisition_status = "attempted_not_acquired"
            acquisition_reason = "fetch_attempts_without_verified_local_resource"
        else:
            acquisition_status = "not_attempted"
            acquisition_reason = "no_verified_identity_or_retrieval_target"
        succeeded = [
            item for item in candidate_readings if item["result_status"] == "succeeded"
        ]
        if succeeded:
            reading_status = "succeeded"
            reading_reason = "input_bound_fulltext_reading_result_available"
        elif candidate_resources:
            reading_status = "pending"
            reading_reason = "verified_resource_without_successful_reading_run"
        else:
            reading_status = "not_applicable_yet"
            reading_reason = "no_verified_local_resource"
        resource_ids = [str(item["resource_id"]) for item in candidate_resources]
        cells = (
            source_id,
            str(row["clue_id"]),
            str(row["entity_kind"]),
            str(row["domain_category"] or ""),
            research_urns,
            candidate_locators,
            len(candidate_locators),
            str(row["clue_status"]),
            str(row["candidate_status"]),
            _identity_reason(str(row["clue_status"])),
            str(row["paper_id"]) if row["paper_id"] else None,
            str(row["canonical_urn"]) if row["canonical_urn"] else None,
            acquisition_status,
            acquisition_reason,
            candidate_fetches,
            resource_ids,
            [f"/api/v1/evidence/resources/{resource_id}" for resource_id in resource_ids],
            reading_status,
            reading_reason,
            [str(item["reading_run_id"]) for item in candidate_readings],
            json.loads(str(row["raw_claim_json"])),
        )
        lines.append("\t".join(_json_cell(value) for value in cells))
    if len(lines) != len(base_rows) + 3:
        raise EvidenceConflict("candidate inventory line conservation failed")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _ensure_export_directory(root: Path) -> Path:
    ensure_no_reparse_components(root)
    root.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(root)
    directory = root / "exports"
    ensure_no_reparse_components(directory)
    directory.mkdir(exist_ok=True)
    ensure_no_reparse_components(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise EvidenceConflict("inventory export directory is unsafe")
    return directory


def _read_regular_single_link(path: Path) -> bytes:
    info = path.lstat()
    if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise EvidenceConflict("inventory export is not a regular single-link file")
    return path.read_bytes()


def _atomic_write_new_or_equal(path: Path, payload: bytes) -> bool:
    if os.path.lexists(path):
        if _read_regular_single_link(path) != payload:
            raise EvidenceConflict("deterministic inventory path contains different bytes")
        return False
    descriptor, temporary_name = tempfile.mkstemp(prefix=".qrh-inventory-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if hashlib.sha256(temporary.read_bytes()).digest() != hashlib.sha256(payload).digest():
            raise EvidenceConflict("temporary inventory verification failed")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if _read_regular_single_link(path) != payload:
        raise EvidenceConflict("atomic inventory finalize verification failed")
    return True


def export_inventory(settings: Settings) -> InventoryExport:
    repository = EvidenceRepository(settings)
    repository.initialize()
    snapshot_hash = repository.snapshot_hash()
    payload = inventory_bytes(settings)
    digest = hashlib.sha256(payload).hexdigest()
    relative_path = f"exports/research-papers-{snapshot_hash}.txt"
    export_id = stable_evidence_id(
        "export", INVENTORY_FORMAT_VERSION, snapshot_hash, digest
    )
    target = _ensure_export_directory(settings.research_papers_root) / Path(relative_path).name

    with evidence_connection(settings) as connection:
        existing = connection.execute(
            """
            SELECT * FROM paper_inventory_export
            WHERE source_snapshot_hash=? AND format_version=?
            """,
            (snapshot_hash, INVENTORY_FORMAT_VERSION),
        ).fetchone()
    if existing is not None:
        expected = (export_id, digest, len(payload), relative_path)
        actual = (
            existing["export_id"],
            existing["content_sha256"],
            existing["bytes"],
            existing["relative_path"],
        )
        if actual != expected:
            raise EvidenceConflict("inventory registry conflicts with deterministic bytes")
        _atomic_write_new_or_equal(target, payload)
        return InventoryExport(
            export_id, snapshot_hash, digest, len(payload), relative_path, False
        )

    created = _atomic_write_new_or_equal(target, payload)
    with evidence_connection(settings) as connection, immediate_transaction(connection):
        concurrent = connection.execute(
            """
            SELECT * FROM paper_inventory_export
            WHERE source_snapshot_hash=? AND format_version=?
            """,
            (snapshot_hash, INVENTORY_FORMAT_VERSION),
        ).fetchone()
        if concurrent is None:
            connection.execute(
                """
                INSERT INTO paper_inventory_export(
                    export_id,source_snapshot_hash,format_version,content_sha256,
                    bytes,relative_path,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    export_id,
                    snapshot_hash,
                    INVENTORY_FORMAT_VERSION,
                    digest,
                    len(payload),
                    relative_path,
                    utc_now(),
                ),
            )
        elif (
            concurrent["export_id"],
            concurrent["content_sha256"],
            concurrent["bytes"],
            concurrent["relative_path"],
        ) != (export_id, digest, len(payload), relative_path):
            raise EvidenceConflict("concurrent deterministic inventory conflicts")
    return InventoryExport(
        export_id, snapshot_hash, digest, len(payload), relative_path, created
    )


def export_candidate_inventory(settings: Settings) -> InventoryExport:
    repository = EvidenceRepository(settings)
    repository.initialize()
    snapshot_hash = repository.snapshot_hash()
    payload = candidate_inventory_bytes(settings)
    digest = hashlib.sha256(payload).hexdigest()
    relative_path = f"exports/research-paper-candidates-{snapshot_hash}.txt"
    export_id = stable_evidence_id(
        "export", CANDIDATE_INVENTORY_FORMAT_VERSION, snapshot_hash, digest
    )
    target = _ensure_export_directory(settings.research_papers_root) / Path(
        relative_path
    ).name

    with evidence_connection(settings) as connection:
        existing = connection.execute(
            """
            SELECT * FROM paper_inventory_export
            WHERE source_snapshot_hash=? AND format_version=?
            """,
            (snapshot_hash, CANDIDATE_INVENTORY_FORMAT_VERSION),
        ).fetchone()
    if existing is not None:
        expected = (export_id, digest, len(payload), relative_path)
        actual = (
            existing["export_id"],
            existing["content_sha256"],
            existing["bytes"],
            existing["relative_path"],
        )
        if actual != expected:
            raise EvidenceConflict("candidate inventory registry conflicts with deterministic bytes")
        _atomic_write_new_or_equal(target, payload)
        return InventoryExport(
            export_id, snapshot_hash, digest, len(payload), relative_path, False
        )

    created = _atomic_write_new_or_equal(target, payload)
    with evidence_connection(settings) as connection, immediate_transaction(connection):
        concurrent = connection.execute(
            """
            SELECT * FROM paper_inventory_export
            WHERE source_snapshot_hash=? AND format_version=?
            """,
            (snapshot_hash, CANDIDATE_INVENTORY_FORMAT_VERSION),
        ).fetchone()
        if concurrent is None:
            connection.execute(
                """
                INSERT INTO paper_inventory_export(
                    export_id,source_snapshot_hash,format_version,content_sha256,
                    bytes,relative_path,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    export_id,
                    snapshot_hash,
                    CANDIDATE_INVENTORY_FORMAT_VERSION,
                    digest,
                    len(payload),
                    relative_path,
                    utc_now(),
                ),
            )
        elif (
            concurrent["export_id"],
            concurrent["content_sha256"],
            concurrent["bytes"],
            concurrent["relative_path"],
        ) != (export_id, digest, len(payload), relative_path):
            raise EvidenceConflict("concurrent deterministic candidate inventory conflicts")
    return InventoryExport(
        export_id, snapshot_hash, digest, len(payload), relative_path, created
    )
