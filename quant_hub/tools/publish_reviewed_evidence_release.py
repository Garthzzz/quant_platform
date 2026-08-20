"""消费独立 PASS gate，以可恢复、可密封方式发布 Evidence release。"""

from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import sys
from typing import Iterator


SCRIPT_PATH = Path(__file__).resolve()
FORMAL_ROOT = SCRIPT_PATH.parents[1]
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.config import Settings
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.presentation_contract import (
    ChineseOverlayContractError,
    OVERLAY_SCHEMA,
    build_chinese_overlay_contract,
    build_reviewed_arxiv_official_abstract_projection_contract,
    build_reviewed_crossref_official_abstract_projection_contract,
)
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.resources import EvidenceResourceStore
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.platform.workflow import canonical_json
from quant_hub.runtime_seal import (
    RuntimeSealError,
    assert_material,
    database_contract,
    file_identity,
    read_json,
    require_no_sqlite_sidecars,
    runtime_toolchain,
    safe_tree,
    write_new_json,
)


GATE_SCHEMA = "qrh-reviewed-evidence-integration-gate/v2"
ASSEMBLY_SCHEMA = "qrh-reviewed-delivery-assembly-seal/v2"
ACTIVATION_SCHEMA = "qrh-activated-delivery-seal/v1"
PROMOTION_STATE_SCHEMA = "qrh-reviewed-promotion-state/v1"
REQUIRED_REVIEW_KINDS = {
    "assembly_report",
    "crossref_identity_verdict",
    "arxiv_material_verdict",
    "u055_rights_verdict",
    "evidence_replay_report",
    "integration_verdict",
}
DATABASE_NAMES = (
    "platform.sqlite3",
    "archive.sqlite3",
    "research_papers.sqlite3",
    "paper_lab.sqlite3",
)
ASSEMBLY_DATABASE_DOMAINS = {
    "platform.sqlite3": "platform",
    "archive.sqlite3": "archive",
    "research_papers.sqlite3": "research_papers",
    "paper_lab.sqlite3": "paper_lab",
}
MANAGED_TREE_NAMES = (
    "inbox", "objects", "paper_lab", "replay", "research_papers", "exports"
)
ALLOW_SYNTHETIC_TEST_MODE = False
ALLOWED_PROMOTION_TABLES = {
    "platform.sqlite3": {
        "release_candidate",
        "release_decision",
        "release_snapshot",
        "outbox_event",
    },
    "research_papers.sqlite3": {
        "paper_inventory_export",
        "evidence_release",
        "evidence_release_item",
        "platform_certificate_receipt",
        "evidence_release_activation",
        "active_evidence_release",
        "outbox_event",
    },
    "archive.sqlite3": set(),
    "paper_lab.sqlite3": set(),
}
DATABASE_STATE_FIELDS = (
    "bytes",
    "mtime_ns",
    "sha256",
    "integrity",
    "foreign_key_violations",
    "migration_versions",
    "schema_sha256",
)


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeSealError(f"assembly seal omits {label}")
    return value


def _sealed_tree(wrapper: object, *, label: str) -> dict[str, object]:
    value = _mapping(wrapper, label=f"{label} audit wrapper").get("sealed_tree")
    tree = _mapping(value, label=f"{label} sealed tree")
    if set(tree) != {"files", "bytes", "tree_sha256"}:
        raise RuntimeSealError(f"assembly {label} sealed tree has an invalid shape")
    return tree


def _assembly_runtime_contract(assembly: dict[str, object]) -> dict[str, object]:
    wrapper = _mapping(assembly.get("runtime_contract"), label="runtime contract")
    toolchain_wrapper = _mapping(wrapper.get("toolchain"), label="toolchain audit wrapper")
    return {
        "code": _sealed_tree(wrapper.get("code"), label="runtime code"),
        "migrations": _sealed_tree(
            wrapper.get("migrations"), label="runtime migrations"
        ),
        "toolchain": _mapping(
            toolchain_wrapper.get("sealed_contract"),
            label="runtime toolchain sealed contract",
        ),
    }


def _assembly_database_contracts(
    assembly: dict[str, object],
) -> dict[str, dict[str, object]]:
    wrappers = _mapping(assembly.get("databases"), label="database contracts")
    result: dict[str, dict[str, object]] = {}
    for filename, domain in ASSEMBLY_DATABASE_DOMAINS.items():
        wrapper = _mapping(wrappers.get(domain), label=f"database wrapper {domain}")
        contract = _mapping(
            wrapper.get("database_contract"),
            label=f"database sealed contract {domain}",
        )
        expected_hash = wrapper.get("database_contract_sha256")
        actual_hash = hashlib.sha256(
            canonical_json(contract).encode("utf-8")
        ).hexdigest()
        if expected_hash != actual_hash:
            raise RuntimeSealError(
                f"assembly database contract hash differs from its audit wrapper: {domain}"
            )
        if not isinstance(contract.get("tables"), dict):
            raise RuntimeSealError(f"assembly database omits table seals: {domain}")
        result[filename] = contract
    return result


def _assembly_managed_trees(
    assembly: dict[str, object],
) -> dict[str, dict[str, object]]:
    wrappers = _mapping(assembly.get("managed_trees"), label="managed trees")
    return {
        name: _sealed_tree(wrappers.get(name), label=f"managed tree {name}")
        for name in MANAGED_TREE_NAMES
    }


def _assembly_resource_contract(assembly: dict[str, object]) -> dict[str, object]:
    wrapper = _mapping(assembly.get("resource_contract"), label="resource contract")
    return _mapping(
        wrapper.get("sealed_contract"), label="resource sealed contract"
    )


def _database_states(
    contracts: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    return {
        name: {field: contract[field] for field in DATABASE_STATE_FIELDS}
        for name, contract in contracts.items()
    }


def _sha256(path: Path) -> str:
    return str(file_identity(path)["sha256"])


def _evidence_counts(settings: Settings) -> dict[str, int]:
    evidence_query = EvidenceQueryService(settings)
    with evidence_connection(settings) as connection:
        queries = {
            "canonical_papers": "SELECT count(*) FROM paper",
            "verified_resources": (
                "SELECT count(*) FROM paper_resource "
                "WHERE verification_status='verified'"
            ),
            "canonicalization_receipts": (
                "SELECT count(*) FROM evidence_canonicalization_receipt"
            ),
            "formal_receipts": (
                "SELECT count(*) FROM evidence_canonicalization_receipt "
                "WHERE treatment='formal_citation'"
            ),
            "method_receipts": (
                "SELECT count(*) FROM evidence_canonicalization_receipt "
                "WHERE treatment='associated_method_origin'"
            ),
            "blocked_acquisitions": (
                "SELECT count(*) FROM evidence_acquisition_state WHERE state='blocked'"
            ),
            "associated_method_ledger_occurrences": (
                "SELECT count(DISTINCT ledger_entry_id) "
                "FROM evidence_associated_method_relation"
            ),
            "fulltext_conclusion_support": (
                "SELECT count(*) FROM evidence_fulltext_conclusion_support"
            ),
            "official_abstract_excerpts": "SELECT count(*) FROM evidence_excerpt",
            "reviewed_arxiv_official_abstracts": """
                SELECT count(DISTINCT excerpt.excerpt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN identifier_assignment_projection AS identifier
                  ON identifier.paper_id=receipt.paper_id
                 AND identifier.scheme='arxiv'
                JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
            """,
            "reviewed_crossref_official_abstracts": """
                SELECT count(DISTINCT excerpt.excerpt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN identifier_assignment_projection AS identifier
                  ON identifier.paper_id=receipt.paper_id
                 AND identifier.scheme='doi'
                JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
                WHERE json_extract(excerpt.locator_json,'$.field')=
                      'crossref.message.abstract'
            """,
            "core_conclusions": "SELECT count(*) FROM paper_core_conclusion",
            "reviewed_open_pdf_resources": """
                SELECT count(*)
                FROM paper_resource AS resource
                JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
                WHERE fetch.source_request_id LIKE 'reviewed-open-pdf:%'
                  AND fetch.result_status='succeeded'
                  AND fetch.rights_status='verified_open_license'
                  AND resource.verification_status='verified'
            """,
            "formal_resolved_ledger_entries": """
                SELECT count(*) FROM citation_binding_projection AS projection
                JOIN citation_binding AS binding USING(binding_id)
                WHERE binding.binding_status='resolved'
            """,
            "associated_method_relations": (
                "SELECT count(*) FROM evidence_associated_method_relation"
            ),
            "method_origin_derivations": (
                "SELECT count(*) FROM evidence_method_origin_candidate_derivation"
            ),
        }
        counts = {
            name: int(connection.execute(query).fetchone()[0])
            for name, query in queries.items()
        }
        listed_papers = evidence_query.list_papers(limit=500)["papers"]
        paper_ids = {str(paper["paper_id"]) for paper in listed_papers}
        paper_titles = {
            str(paper["paper_id"]): str(paper.get("title") or "")
            for paper in listed_papers
        }
        relation_rows = evidence_query._archive_relation_rows_by_paper(
            connection, paper_ids
        )
        archive_index = evidence_query._archive_link_index()
        legacy_current_coverage = 0
        for paper_id in paper_ids:
            rows = relation_rows.get(paper_id, [])
            current_core = [
                relation
                for relation in evidence_query._present_archive_relations(
                    rows,
                    archive_index,
                    core_only=True,
                    paper_title=paper_titles.get(paper_id, ""),
                )
                if relation.get("source_resolution") == "current_archive_document"
            ]
            current_relations = [
                relation
                for relation in evidence_query._present_archive_relations(
                    rows,
                    archive_index,
                    paper_title=paper_titles.get(paper_id, ""),
                )
                if relation.get("source_resolution") == "current_archive_document"
            ]
            current_references = (
                []
                if current_core
                else evidence_query._select_archive_reference_relations(
                    current_relations
                )
            )
            legacy_current_coverage += bool(current_core or current_references)
    receipt = read_json(
        settings.research_papers_root
        / "exports"
        / "reviewed_total_gate_receipt.json",
        schema_version="qrh-reviewed-evidence-gate-receipt/v1",
    )
    release_expectation = receipt.get("release_expectation")
    if not isinstance(release_expectation, dict):
        raise RuntimeSealError("reviewed Evidence receipt omits release expectation")
    reviewed_displayable = release_expectation.get(
        "displayable_archive_relation_papers"
    )
    if not isinstance(reviewed_displayable, int) or reviewed_displayable < 0:
        raise RuntimeSealError(
            "reviewed Evidence receipt has invalid historical relation coverage"
        )
    counts["displayable_archive_relation_papers"] = reviewed_displayable
    counts["current_exact_archive_relation_papers"] = legacy_current_coverage
    counts["effective_displayable_archive_relation_papers"] = sum(
        bool(paper["dossier_coverage"]["archive_relations"])
        for paper in listed_papers
    )
    return counts


def _chinese_overlay_contract(
    settings: Settings, expected_entries: int
) -> dict[str, object]:
    if ALLOW_SYNTHETIC_TEST_MODE and expected_entries == 0:
        return {
            "schema_version": OVERLAY_SCHEMA,
            "status": "not_applicable_no_official_abstracts",
            "entries": 0,
            "excluded": 0,
            "database_official_abstracts": 0,
        }
    try:
        contract = build_chinese_overlay_contract(
            settings.research_papers_database_path,
            SOURCE_ROOT / "quant_hub" / "presentation" / "evidence_zh_overlays.json",
        )
    except ChineseOverlayContractError as error:
        raise RuntimeSealError(f"正式中文展示层未通过发布门禁：{error}") from error
    if (
        contract["entries"] != expected_entries
        or contract["database_official_abstracts"] != expected_entries
    ):
        raise RuntimeSealError("正式中文展示层覆盖数与审核收据不一致")
    return contract


def _official_abstract_projection_contract(settings: Settings) -> dict[str, object]:
    try:
        return build_reviewed_arxiv_official_abstract_projection_contract(
            settings.research_papers_database_path
        )
    except ChineseOverlayContractError as error:
        raise RuntimeSealError(
            f"reviewed arXiv 官方摘要投影无法从候选重建：{error}"
        ) from error


def _crossref_official_abstract_projection_contract(
    settings: Settings,
) -> dict[str, object]:
    try:
        return build_reviewed_crossref_official_abstract_projection_contract(
            settings.research_papers_database_path
        )
    except ChineseOverlayContractError as error:
        raise RuntimeSealError(
            f"reviewed Crossref 官方摘要投影无法从候选重建：{error}"
        ) from error


def _resource_contract(settings: Settings) -> dict[str, object]:
    store = EvidenceResourceStore(settings)
    with evidence_connection(settings) as connection:
        rows = list(
            connection.execute(
                """
                SELECT resource_id,verification_status,media_type,content_sha256,
                       bytes,relative_path
                FROM paper_resource ORDER BY resource_id
                """
            )
        )
    expected_object_records: list[tuple[str, int, str]] = []
    items: list[dict[str, object]] = []
    for row in rows:
        relative = PurePosixPath(str(row["relative_path"]))
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in str(row["relative_path"])
        ):
            raise RuntimeSealError("paper_resource has a non-canonical relative path")
        relative_text = relative.as_posix()
        if not relative.parts or relative.parts[0] != "objects":
            raise RuntimeSealError("paper_resource path is outside the objects subtree")
        path = settings.research_papers_root.joinpath(*relative.parts)
        identity = file_identity(path)
        if (
            identity["bytes"] != int(row["bytes"])
            or identity["sha256"] != str(row["content_sha256"])
            or str(row["media_type"]) != "application/pdf"
        ):
            raise RuntimeSealError(f"paper resource bytes do not match DB: {row['resource_id']}")
        if str(row["verification_status"]) != "verified":
            raise RuntimeSealError("locally stored paper_resource is not verified")
        response = store.resource_response(str(row["resource_id"]))
        if (
            not response.payload.startswith(b"%PDF-")
            or hashlib.sha256(response.payload).hexdigest() != identity["sha256"]
        ):
            raise RuntimeSealError("public resource response differs from sealed bytes")
        expected_object_records.append(
            (
                PurePosixPath(*relative.parts[1:]).as_posix(),
                int(identity["bytes"]),
                str(identity["sha256"]),
            )
        )
        items.append(
            {
                "resource_id": str(row["resource_id"]),
                "relative_path": relative_text,
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
            }
        )
    object_root = settings.research_papers_root / "objects"
    expected_digest = hashlib.sha256()
    expected_bytes = 0
    for relative_path, size, digest in sorted(expected_object_records):
        expected_digest.update(relative_path.encode("utf-8"))
        expected_digest.update(b"\0")
        expected_digest.update(str(size).encode("ascii"))
        expected_digest.update(b"\0")
        expected_digest.update(digest.encode("ascii"))
        expected_digest.update(b"\n")
        expected_bytes += size
    expected_object_tree = {
        "files": len(expected_object_records),
        "bytes": expected_bytes,
        "tree_sha256": expected_digest.hexdigest(),
    }
    actual_object_tree = safe_tree(object_root)
    if actual_object_tree != expected_object_tree:
        raise RuntimeSealError("research_papers objects and paper_resource rows are not closed")
    return {
        "resources": len(items),
        "items_sha256": hashlib.sha256(
            canonical_json(items).encode("utf-8")
        ).hexdigest(),
        "objects": actual_object_tree,
    }


def _database_contracts(delivery: Path) -> dict[str, dict[str, object]]:
    paths = [delivery / "db" / name for name in DATABASE_NAMES]
    require_no_sqlite_sidecars(paths)
    return {name: database_contract(delivery / "db" / name) for name in DATABASE_NAMES}


def _nonpromotion_tables(
    contracts: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for name, contract in contracts.items():
        tables = contract.get("tables")
        if not isinstance(tables, dict):
            raise RuntimeSealError(f"database contract omits table seals: {name}")
        allowed = ALLOWED_PROMOTION_TABLES[name]
        result[name] = {
            table_name: table_state
            for table_name, table_state in tables.items()
            if table_name not in allowed
        }
    return result


def _write_state(path: Path, state: dict[str, object]) -> None:
    rendered = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"0")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise RuntimeSealError("another promotion process owns this delivery") from error
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise RuntimeSealError("another promotion process owns this delivery") from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _maybe_fail(requested: str | None, phase: str) -> None:
    if requested == phase:
        raise RuntimeError(f"injected promotion failure after {phase}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--delivery-var", type=Path, required=True)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--fail-after-phase",
        choices=("preflight", "candidate", "decision", "snapshot", "activation", "seal"),
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    workspace = args.project_root.resolve(strict=True)
    delivery = args.delivery_var.resolve(strict=True)
    delivery_root = (workspace / "quant_hub" / "var").resolve(strict=True)
    if delivery == delivery_root or not delivery.is_relative_to(delivery_root):
        raise RuntimeSealError("delivery-var must be a child of quant_hub/var")
    expected_script = delivery / "runtime_contract" / "code" / "tools" / SCRIPT_PATH.name
    if SCRIPT_PATH != expected_script.resolve(strict=True):
        raise RuntimeSealError("publisher must execute from the frozen delivery code")

    audit_root = (workspace / "project_state").resolve(strict=True)
    gate_path = args.gate.resolve(strict=True)
    report_path = args.report.resolve(strict=False)
    if not gate_path.is_file() or not gate_path.is_relative_to(audit_root):
        raise RuntimeSealError("gate must be a file under project_state")
    report_root = (audit_root / "gates").resolve(strict=True)
    if (
        report_path == report_root
        or not report_path.is_relative_to(report_root)
        or report_path.exists()
    ):
        raise RuntimeSealError("report must be a new file under project_state/gates")

    gate_identity_before = file_identity(gate_path)
    gate_bytes = gate_path.read_bytes()
    if hashlib.sha256(gate_bytes).hexdigest() != gate_identity_before["sha256"]:
        raise RuntimeSealError("integration gate changed while being read")
    gate = read_json(gate_path, schema_version=GATE_SCHEMA)
    assert_material(
        file_identity(gate_path), gate_identity_before, label="integration gate"
    )
    if gate.get("status") != "PASS":
        raise RuntimeSealError("release requires an independent PASS integration gate")
    if Path(str(gate.get("delivery_var", ""))).resolve(strict=True) != delivery:
        raise RuntimeSealError("integration gate is bound to a different delivery")

    assembly_path = delivery / "ASSEMBLY_SEAL.json"
    assembly_identity_before = file_identity(assembly_path)
    assembly = read_json(assembly_path, schema_version=ASSEMBLY_SCHEMA)
    assert_material(
        file_identity(assembly_path), assembly_identity_before, label="assembly seal"
    )
    assembly_hash = str(assembly_identity_before["sha256"])
    if assembly.get("status") != "PASS":
        raise RuntimeSealError("release requires a PASS assembly seal")
    synthetic_test_mode = assembly.get("synthetic_test_mode")
    if not isinstance(synthetic_test_mode, bool):
        raise RuntimeSealError("assembly seal omits its synthetic-test boundary")
    if synthetic_test_mode and not ALLOW_SYNTHETIC_TEST_MODE:
        raise RuntimeSealError("synthetic test assembly cannot be published")
    if assembly_hash != gate.get("assembly_seal_sha256"):
        raise RuntimeSealError("assembly seal differs from the reviewed gate")
    assembly_active_runtime = _assembly_runtime_contract(assembly)
    assembly_database_contracts = _assembly_database_contracts(assembly)
    assembly_managed_trees = _assembly_managed_trees(assembly)
    assembly_resource_contract = _assembly_resource_contract(assembly)

    artifacts = gate.get("review_artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeSealError("integration gate has no review artifacts")
    observed_kinds: set[str] = set()
    review_hashes: list[str] = []
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeSealError("review artifact entry is invalid")
        kind = str(item.get("kind", ""))
        path = Path(str(item.get("path", ""))).resolve(strict=True)
        if not path.is_file() or not path.is_relative_to(audit_root):
            raise RuntimeSealError(f"review artifact is outside project_state: {path}")
        digest = _sha256(path)
        if digest != item.get("sha256"):
            raise RuntimeSealError(f"review artifact hash changed: {path}")
        observed_kinds.add(kind)
        review_hashes.append(digest)
    missing_kinds = REQUIRED_REVIEW_KINDS - observed_kinds
    if missing_kinds:
        raise RuntimeSealError(
            "integration gate is missing required review kinds: "
            + ", ".join(sorted(missing_kinds))
        )

    frozen_migrations = delivery / "runtime_contract" / "migrations"
    settings = Settings.default(
        project_root=workspace,
        var_root=delivery,
        migration_root=frozen_migrations / "platform",
    )
    settings.validate_reviewed_runtime()
    state_path = delivery / "PROMOTION_STATE.json"
    lock_path = delivery / "PROMOTION.lock"
    activation_path = delivery / "ACTIVATED_DELIVERY_SEAL.json"

    with _exclusive_lock(lock_path):
        if state_path.exists():
            state = read_json(state_path, schema_version=PROMOTION_STATE_SCHEMA)
            if (
                state.get("assembly_seal_sha256") != assembly_hash
                or state.get("gate_sha256") != hashlib.sha256(gate_bytes).hexdigest()
            ):
                raise RuntimeSealError("promotion state belongs to different reviewed material")
            current_contracts = _database_contracts(delivery)
            assert_material(
                _nonpromotion_tables(current_contracts),
                state.get("sealed_nonpromotion_tables"),
                label="non-promotion database tables during recovery",
            )
            assembly_sources = assembly.get("source_integrity")
            if not isinstance(assembly_sources, dict):
                raise RuntimeSealError("assembly seal is incomplete during recovery")
            assert_material(
                safe_tree(
                    delivery / "runtime_contract" / "code",
                    exclude_runtime_caches=True,
                ),
                assembly_active_runtime["code"],
                label="recovery runtime code",
            )
            assert_material(
                safe_tree(frozen_migrations),
                assembly_active_runtime["migrations"],
                label="recovery migrations",
            )
            assert_material(
                runtime_toolchain(),
                assembly_active_runtime["toolchain"],
                label="recovery toolchain",
            )
            schema_fields = (
                "integrity",
                "foreign_key_violations",
                "migration_versions",
                "schema_sha256",
            )
            for name in DATABASE_NAMES:
                expected_database = assembly_database_contracts[name]
                assert_material(
                    {field: current_contracts[name].get(field) for field in schema_fields},
                    {field: expected_database.get(field) for field in schema_fields},
                    label=f"recovery database schema {name}",
                )
            for name in MANAGED_TREE_NAMES:
                assert_material(
                    safe_tree(delivery / name),
                    assembly_managed_trees[name],
                    label=f"recovery managed tree {name}",
                )
            assert_material(
                safe_tree(workspace / "reference" / "archive"),
                assembly_sources.get("archive"),
                label="recovery reference/archive",
            )
            assert_material(
                safe_tree(workspace / "reference" / "proj2"),
                assembly_sources.get("proj2"),
                label="recovery reference/proj2",
            )
            assert_material(
                _resource_contract(settings),
                assembly_resource_contract,
                label="recovery resource contract",
            )
        else:
            assert_material(
                safe_tree(delivery / "runtime_contract" / "code", exclude_runtime_caches=True),
                assembly_active_runtime["code"],
                label="assembly runtime code",
            )
            assert_material(
                safe_tree(frozen_migrations),
                assembly_active_runtime["migrations"],
                label="assembly migrations",
            )
            assert_material(
                runtime_toolchain(),
                assembly_active_runtime["toolchain"],
                label="assembly toolchain",
            )
            current_contracts = _database_contracts(delivery)
            assert_material(
                current_contracts,
                assembly_database_contracts,
                label="assembly databases",
            )
            for name in MANAGED_TREE_NAMES:
                assert_material(
                    safe_tree(delivery / name),
                    assembly_managed_trees[name],
                    label=f"assembly managed tree {name}",
                )
            source_integrity = assembly.get("source_integrity")
            if not isinstance(source_integrity, dict):
                raise RuntimeSealError("assembly seal omits source integrity")
            assert_material(
                safe_tree(workspace / "reference" / "archive"),
                source_integrity.get("archive"),
                label="reference/archive",
            )
            assert_material(
                safe_tree(workspace / "reference" / "proj2"),
                source_integrity.get("proj2"),
                label="reference/proj2",
            )
            assert_material(
                _resource_contract(settings),
                assembly_resource_contract,
                label="assembly resource contract",
            )
            state = {
                "schema_version": PROMOTION_STATE_SCHEMA,
                "status": "in_progress",
                "phase": "preflight",
                "started_at": datetime.now(UTC).isoformat(),
                "delivery_var": str(delivery),
                "assembly_seal_sha256": assembly_hash,
                "gate_sha256": hashlib.sha256(gate_bytes).hexdigest(),
                "sealed_nonpromotion_tables": _nonpromotion_tables(current_contracts),
            }
            _write_state(state_path, state)
        _maybe_fail(args.fail_after_phase, "preflight")

        service = EvidenceReleaseService(settings)
        prepared = service.prepare_candidate()
        actual_spec = asdict(prepared.candidate_spec)
        expected_evidence = assembly.get("evidence")
        if not isinstance(expected_evidence, dict):
            raise RuntimeSealError("assembly seal omits Evidence candidate")
        assert_material(actual_spec, expected_evidence.get("candidate_spec"), label="candidate spec")
        assert_material(actual_spec, gate.get("candidate_spec"), label="reviewed candidate spec")
        if prepared.evidence_release_id != expected_evidence.get("evidence_release_id"):
            raise RuntimeSealError("Evidence release ID differs from assembly")
        actual_counts = _evidence_counts(settings)
        assert_material(actual_counts, expected_evidence.get("counts"), label="assembly counts")
        assert_material(actual_counts, gate.get("evidence_counts"), label="reviewed counts")
        chinese_overlay_contract = _chinese_overlay_contract(
            settings, actual_counts["official_abstract_excerpts"]
        )
        assert_material(
            chinese_overlay_contract,
            expected_evidence.get("chinese_overlay_contract"),
            label="assembly Chinese overlay contract",
        )
        official_abstract_projection_contract = (
            _official_abstract_projection_contract(settings)
        )
        assert_material(
            official_abstract_projection_contract,
            expected_evidence.get("official_abstract_projection_contract"),
            label="assembly official abstract projection contract",
        )
        crossref_official_abstract_projection_contract = (
            _crossref_official_abstract_projection_contract(settings)
        )
        assert_material(
            crossref_official_abstract_projection_contract,
            expected_evidence.get(
                "crossref_official_abstract_projection_contract"
            ),
            label="assembly Crossref official abstract projection contract",
        )
        if service.repository.snapshot_hash() != expected_evidence.get("repository_snapshot_hash"):
            raise RuntimeSealError("Evidence repository snapshot differs from assembly")
        assert_material(
            _resource_contract(settings),
            assembly_resource_contract,
            label="pre-publish resources",
        )

        gate_hash = hashlib.sha256(gate_bytes).hexdigest()
        deterministic_gate_hash = stable_sha256(
            "reviewed-evidence-integration-gate/v2",
            gate_hash,
            assembly_hash,
            prepared.candidate_spec.artifact_manifest_hash,
        )
        review_set_hash = stable_sha256(
            "reviewed-evidence-review-set/v2", *sorted(review_hashes)
        )
        reconciliation_policy = str(gate.get("reconciliation_policy") or "").strip()
        if not reconciliation_policy:
            raise RuntimeSealError("integration gate has no reconciliation policy")
        reconciliation_hash = stable_sha256(
            "reviewed-evidence-reconciliation/v2",
            canonical_json(actual_counts),
            reconciliation_policy,
        )

        authority = ReleaseAuthority(settings)
        registration = authority.register_candidate(prepared.candidate_spec)
        state.update(
            phase="candidate",
            candidate_id=registration.candidate_id,
        )
        _write_state(state_path, state)
        _maybe_fail(args.fail_after_phase, "candidate")

        decision = authority.decision_for_candidate(registration.candidate_id)
        reused_domain_decision = decision is not None
        if decision is None:
            decision = authority.record_decision(
                registration.candidate_id,
                deterministic_gate_hash=deterministic_gate_hash,
                review_set_hash=review_set_hash,
                reconciliation_hash=reconciliation_hash,
                verdict="pass",
            )
        elif decision.verdict != "pass":
            raise RuntimeSealError(
                "existing immutable Evidence decision is not PASS"
            )
        state.update(phase="decision", decision_id=decision.decision_id)
        _write_state(state_path, state)
        _maybe_fail(args.fail_after_phase, "decision")

        certificate = authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
            issuance_key=stable_sha256(
                "reviewed-evidence-release-issuance/v2",
                gate_hash,
                assembly_hash,
                prepared.candidate_spec.artifact_manifest_hash,
            ),
        )
        state.update(phase="snapshot", release_snapshot_urn=certificate.snapshot_urn)
        _write_state(state_path, state)
        _maybe_fail(args.fail_after_phase, "snapshot")

        published = service.publish(prepared, certificate)
        repeated = service.publish(prepared, certificate)
        if repeated.created:
            raise RuntimeSealError("Evidence release activation was not idempotent")
        authority.verify_snapshot(
            certificate.snapshot_urn, decision.decision_hash, prepared.candidate_spec
        )
        state.update(
            phase="activation",
            activation_id=published.activation_id,
            evidence_release_id=prepared.evidence_release_id,
        )
        _write_state(state_path, state)
        _maybe_fail(args.fail_after_phase, "activation")

        post_contracts = _database_contracts(delivery)
        assert_material(
            _nonpromotion_tables(post_contracts),
            state.get("sealed_nonpromotion_tables"),
            label="post-publish non-promotion tables",
        )
        assert_material(_evidence_counts(settings), actual_counts, label="post-publish counts")
        assert_material(
            _chinese_overlay_contract(
                settings, actual_counts["official_abstract_excerpts"]
            ),
            chinese_overlay_contract,
            label="post-publish Chinese overlay contract",
        )
        assert_material(
            _official_abstract_projection_contract(settings),
            official_abstract_projection_contract,
            label="post-publish official abstract projection contract",
        )
        assert_material(
            _crossref_official_abstract_projection_contract(settings),
            crossref_official_abstract_projection_contract,
            label="post-publish Crossref official abstract projection contract",
        )
        if service.repository.snapshot_hash() != expected_evidence.get("repository_snapshot_hash"):
            raise RuntimeSealError("Evidence snapshot changed during publish")
        resource_contract = _resource_contract(settings)
        assert_material(
            resource_contract,
            assembly_resource_contract,
            label="post-publish resources",
        )
        runtime_contract = {
            "code": safe_tree(
                delivery / "runtime_contract" / "code",
                exclude_runtime_caches=True,
            ),
            "migrations": safe_tree(frozen_migrations),
            "toolchain": runtime_toolchain(),
        }
        assert_material(
            runtime_contract,
            assembly_active_runtime,
            label="runtime contract",
        )
        managed_trees = {
            name: safe_tree(delivery / name) for name in MANAGED_TREE_NAMES
        }
        assert_material(
            managed_trees,
            assembly_managed_trees,
            label="managed trees",
        )
        source_integrity = {
            "archive": safe_tree(workspace / "reference" / "archive"),
            "proj2": safe_tree(workspace / "reference" / "proj2"),
        }
        assert_material(source_integrity, assembly.get("source_integrity"), label="sources")

        activation_payload = {
            "schema_version": ACTIVATION_SCHEMA,
            "status": "PASS",
            "delivery_var": str(delivery),
            "assembly_seal_sha256": assembly_hash,
            "integration_gate_sha256": gate_hash,
            "sealed_at": state["started_at"],
            "runtime_contract": runtime_contract,
            "databases": _database_states(post_contracts),
            "managed_trees": managed_trees,
            "source_integrity": source_integrity,
            "resource_contract": resource_contract,
            "evidence": {
                "candidate_spec": actual_spec,
                "counts": actual_counts,
                "repository_snapshot_hash": expected_evidence["repository_snapshot_hash"],
                "evidence_release_id": prepared.evidence_release_id,
                "activation_id": published.activation_id,
                "release_snapshot_urn": certificate.snapshot_urn,
                "active_revision": published.active_revision,
            },
        }
        if activation_path.exists():
            assert_material(
                read_json(activation_path, schema_version=ACTIVATION_SCHEMA),
                activation_payload,
                label="existing activation seal",
            )
            activation_hash = _sha256(activation_path)
        else:
            activation_hash = write_new_json(activation_path, activation_payload)
        state.update(
            phase="seal",
            status="complete",
            activation_seal_sha256=activation_hash,
        )
        _write_state(state_path, state)
        _maybe_fail(args.fail_after_phase, "seal")

        report = {
            "schema_version": "qrh-reviewed-evidence-promotion/v2",
            "status": "PASS",
            "delivery_var": str(delivery),
            "assembly_seal_sha256": assembly_hash,
            "gate_sha256": gate_hash,
            "activation_seal_path": str(activation_path),
            "activation_seal_sha256": activation_hash,
            "candidate_spec": actual_spec,
            "evidence_counts": actual_counts,
            "candidate_id": registration.candidate_id,
            "decision_id": decision.decision_id,
            "decision_hash": decision.decision_hash,
            "release_snapshot_urn": certificate.snapshot_urn,
            "reused_domain_decision": reused_domain_decision,
            "evidence_release_id": prepared.evidence_release_id,
            "activation_id": published.activation_id,
            "active_revision": published.active_revision,
            "recovered_or_idempotent": not published.created,
            "database_contracts": post_contracts,
            "resource_contract": resource_contract,
        }
        rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
