"""密封组装一个全新的、可独立审核的 Quant Research Hub 候选运行根。

本工具只读取两个已经静止的候选输入和工作树中的已审核代码/迁移，绝不覆盖
现有运行根。输出只有在路径、字节、SQLite schema、Evidence 资源闭包以及预发布
候选都完成校验后才会得到 ``ASSEMBLY_SEAL.json``；外部报告再以 SHA-256 绑定该
seal。没有外部 PASS 报告的残留目录不是可发布候选。
"""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
from importlib import metadata as importlib_metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import sys
import tomllib
from typing import Callable, Iterable


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.config import Settings, stat_is_reparse_point
from quant_hub.evidence.presentation_contract import (
    ChineseOverlayContractError,
    OVERLAY_SCHEMA,
    build_chinese_overlay_contract,
    build_reviewed_arxiv_official_abstract_projection_contract,
    build_reviewed_crossref_official_abstract_projection_contract,
)
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.evidence.releases import EvidenceReleaseService, PreparedEvidenceRelease
from quant_hub.platform.migrations import migrate_up
from quant_hub.reviewed_runtime import (
    _research_update_export_material,
    _validate_research_update_projection,
)
from quant_hub.runtime_seal import (
    RuntimeSealError,
    assert_material,
    canonical_json,
    database_contract as runtime_database_contract,
    database_row_manifest,
    database_state,
    ensure_within,
    file_identity,
    payload_sha256,
    read_json,
    require_no_sqlite_sidecars,
    runtime_toolchain,
    safe_tree,
    write_new_json,
)


SEAL_SCHEMA_VERSION = "qrh-reviewed-delivery-assembly-seal/v2"
REPORT_SCHEMA_VERSION = "qrh-reviewed-delivery-assembly/v2"
REVIEWED_GATE_RECEIPT_SCHEMA = "qrh-reviewed-evidence-gate-receipt/v1"
REVIEWED_GATE_RECEIPT_RELATIVE_PATH = PurePosixPath(
    "exports/reviewed_total_gate_receipt.json"
)
REVIEWED_RELEASE_EXPECTATION_KEYS = frozenset(
    {
        "canonical_papers",
        "verified_resources",
        "canonicalization_receipts",
        "formal_receipts",
        "method_receipts",
        "blocked_acquisitions",
        "associated_method_ledger_occurrences",
        "fulltext_conclusion_support",
        "official_abstract_excerpts",
        "reviewed_arxiv_official_abstracts",
        "reviewed_crossref_official_abstracts",
        "core_conclusions",
        "reviewed_open_pdf_resources",
        "displayable_archive_relation_papers",
    }
)
REVIEWED_RELEASE_EXPECTATION = {
    "canonical_papers": 78,
    "verified_resources": 48,
    "canonicalization_receipts": 60,
    "formal_receipts": 53,
    "method_receipts": 7,
    "blocked_acquisitions": 4,
    "associated_method_ledger_occurrences": 547,
    "fulltext_conclusion_support": 26,
    "official_abstract_excerpts": 53,
    "reviewed_arxiv_official_abstracts": 29,
    "reviewed_crossref_official_abstracts": 6,
    "core_conclusions": 53,
    "reviewed_open_pdf_resources": 4,
    "displayable_archive_relation_papers": 63,
}
REVIEWED_GATE_MATERIAL = {
    "receipt_bytes": 13_926,
    "receipt_sha256": "40502df6f2e861b61aea0092ae1958a6718b26ce0885d7e59f801c2093ce6d05",
    "receipt_payload_sha256": "1f6f04da8c18e7dc9647d87695eaaac5db2bb2f23fff21879870c7c31182c570",
    "input_bindings_sha256": "20eb52bcf76b3e0276906e3adfbec1bee0268483c78b7985a59cc6a9afbbd2e0",
    "dedup_expectation_sha256": "1a6c58a89bff465470ab57b9e793552a6002d201f6574609703e568f1b711cdf",
    "arxiv_subject_sha256": "d2daabc413f2d55964c2697797dad30934249861fbec237c7af03b137144594c",
    "arxiv_official_abstract_expectation_sha256": "172aa565440cb1461e93c7e657dcdb7d9f9375c0edfe8c4e63c491203c41b6f2",
    "crossref_official_abstract_expectation_sha256": "be93700aa8e565360a14a881277a5fedc36e96a716ba2c09d9c190335c1fec4b",
    "open_pdf_review_expectation_sha256": "80762c393732224e035d8ed7515a38dac94fee081f8fc99150cd42f51fd77ca2",
    "static_plan_sha256": "bc10b98af3536ba9ef215f565b6d51aa354194fd6d4d2640a398fcef583f80d0",
}
DATABASE_FILES = {
    "platform": "platform.sqlite3",
    "archive": "archive.sqlite3",
    "research_papers": "research_papers.sqlite3",
    "paper_lab": "paper_lab.sqlite3",
}
MIGRATION_DOMAINS = (*DATABASE_FILES, "research_workspace")
SOURCE_MANAGED_TREES = ("inbox", "objects", "paper_lab", "replay", "exports")
RESEARCH_UPDATE_EXPORT_NAME = "research_update_history.jsonl"
RESEARCH_UPDATE_EXPORT_VALUE_TABLES = {
    "active_research_release",
    "actor",
    "outbox_event",
    "research",
    "research_release",
    "research_release_activation",
    "research_release_candidate_identity",
    "research_update",
    "research_update_annotation_event",
    "research_update_export_checkpoint",
}
RUNTIME_TOOLS = ("run_local.py", "publish_reviewed_evidence_release.py")
PREPARE_MUTABLE_TABLES = frozenset(
    {"paper_inventory_export", "evidence_release", "evidence_release_item"}
)
TOOLCHAIN_RUNTIME_DISTRIBUTIONS = ("werkzeug", "jinja2", "markupsafe")
ASSEMBLER_PATH = Path(__file__).resolve(strict=True)
RUNTIME_SEAL_MODULE_PATH = Path(
    sys.modules["quant_hub.runtime_seal"].__file__
).resolve(strict=True)
PYPROJECT_PATH = FORMAL_ROOT / "pyproject.toml"
# 尽可能靠近模块加载完成点捕获“实际执行字节”，避免稍后才读取文件时把
# 已经被替换的脚本误当成本次进程真正执行的版本。
DEFAULT_EXECUTION_IDENTITIES_AT_IMPORT = {
    "assembler": file_identity(ASSEMBLER_PATH),
    "runtime_seal": file_identity(RUNTIME_SEAL_MODULE_PATH),
    "pyproject": file_identity(PYPROJECT_PATH),
}


@dataclass(frozen=True, slots=True)
class AssemblyPaths:
    workspace: Path
    formal_root: Path
    source_delivery: Path
    evidence_candidate: Path
    output: Path
    report: Path
    archive: Path
    proj2: Path


def _is_same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _real_directory(path: Path, *, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeSealError(f"{label} is missing: {path}") from error
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise RuntimeSealError(f"{label} must be a real directory: {path}")


def _resolve_paths(
    *,
    source_delivery_var: Path,
    evidence_candidate_var: Path,
    output_var: Path,
    report: Path,
    workspace_root: Path,
    formal_root: Path,
) -> AssemblyPaths:
    workspace = workspace_root.resolve(strict=True)
    formal = formal_root.resolve(strict=True)
    if formal.parent != workspace:
        raise RuntimeSealError("formal root must be the workspace quant_hub directory")

    var_root = (formal / "var").resolve(strict=True)
    workers_root = (workspace / "project_state" / "workers").resolve(strict=True)
    gates_root = (workspace / "project_state" / "gates").resolve(strict=True)
    source_delivery = ensure_within(
        source_delivery_var, var_root, label="source-delivery-var"
    ).resolve(strict=True)
    evidence_candidate = ensure_within(
        evidence_candidate_var, workers_root, label="evidence-candidate-var"
    ).resolve(strict=True)
    output = ensure_within(output_var, var_root, label="output-var")
    report_path = ensure_within(report, gates_root, label="report")

    # 运行根必须是 var 的一级、不重叠候选。Evidence replay 允许位于 worker
    # 审计目录的更深层；报告允许在 gate 的命名子目录中。
    if source_delivery.parent != var_root:
        raise RuntimeSealError("source-delivery-var must be a direct child of quant_hub/var")
    if output.parent != var_root:
        raise RuntimeSealError("output-var must be a new direct child of quant_hub/var")
    _real_directory(source_delivery, label="source delivery")
    _real_directory(evidence_candidate, label="Evidence candidate")
    if os.path.lexists(output):
        raise FileExistsError(f"output-var already exists: {output}")
    if os.path.lexists(report_path):
        raise FileExistsError(f"report already exists: {report_path}")
    if _is_same_path(source_delivery, evidence_candidate):
        raise RuntimeSealError("source delivery and Evidence candidate must be distinct")

    archive = (workspace / "reference" / "archive").resolve(strict=True)
    proj2 = (workspace / "reference" / "proj2").resolve(strict=True)
    _real_directory(archive, label="archive reference")
    _real_directory(proj2, label="proj2 reference")
    return AssemblyPaths(
        workspace=workspace,
        formal_root=formal,
        source_delivery=source_delivery,
        evidence_candidate=evidence_candidate,
        output=output,
        report=report_path,
        archive=archive,
        proj2=proj2,
    )


def _tree_records_identity(records: dict[str, dict[str, object]]) -> dict[str, object]:
    digest = hashlib.sha256()
    total_bytes = 0
    for relative, identity in sorted(records.items()):
        size = int(identity["bytes"])
        file_hash = str(identity["sha256"])
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
        total_bytes += size
    return {
        "files": len(records),
        "bytes": total_bytes,
        "tree_sha256": digest.hexdigest(),
    }


def _safe_file_manifest(
    root: Path, *, exclude_runtime_caches: bool = False
) -> dict[str, dict[str, object]]:
    """返回路径到内容身份的安全枚举；不信任 ``rglob`` 的跟随语义。"""

    expected_tree = safe_tree(root, exclude_runtime_caches=exclude_runtime_caches)
    records: dict[str, dict[str, object]] = {}

    def excluded(relative: Path) -> bool:
        return exclude_runtime_caches and (
            any(part == "__pycache__" for part in relative.parts)
            or relative.suffix in {".pyc", ".pyo"}
        )

    def visit(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise RuntimeSealError(f"cannot enumerate managed tree: {directory}") from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise RuntimeSealError(f"cannot stat managed material: {path}") from error
            if entry.is_symlink() or stat_is_reparse_point(info):
                raise RuntimeSealError(f"managed tree contains a link/reparse point: {path}")
            if stat.S_ISDIR(info.st_mode):
                if not excluded(relative):
                    visit(path)
                continue
            if excluded(relative):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeSealError(f"managed tree contains an unsafe entry: {path}")
            identity = file_identity(path)
            records[relative.as_posix()] = {
                "bytes": identity["bytes"],
                "sha256": identity["sha256"],
            }

    visit(root)
    assert_material(
        _tree_records_identity(records), expected_tree, label=f"manifest tree {root}"
    )
    return records


def _reject_reserved_seal_name(
    root: Path, *, exclude_runtime_caches: bool = False
) -> None:
    conflicts = sorted(
        relative
        for relative in _safe_file_manifest(
            root, exclude_runtime_caches=exclude_runtime_caches
        )
        if PurePosixPath(relative).name.casefold() == "assembly_seal.json"
    )
    if conflicts:
        raise RuntimeSealError(
            f"input tree contains reserved ASSEMBLY_SEAL.json name: {conflicts}"
        )


def _copy_tree_contents(
    source: Path, destination: Path, *, exclude_runtime_caches: bool
) -> None:
    def excluded(relative: Path) -> bool:
        return exclude_runtime_caches and (
            any(part == "__pycache__" for part in relative.parts)
            or relative.suffix in {".pyc", ".pyo"}
        )

    def visit(source_directory: Path, destination_directory: Path) -> None:
        entries = sorted(os.scandir(source_directory), key=lambda item: item.name)
        for entry in entries:
            source_path = Path(entry.path)
            relative = source_path.relative_to(source)
            info = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or stat_is_reparse_point(info):
                raise RuntimeSealError(
                    f"managed source contains a link/reparse point: {source_path}"
                )
            destination_path = destination_directory / entry.name
            if stat.S_ISDIR(info.st_mode):
                if excluded(relative):
                    continue
                destination_path.mkdir(exist_ok=False)
                visit(source_path, destination_path)
                continue
            if excluded(relative):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeSealError(f"managed source contains unsafe material: {source_path}")
            source_before = file_identity(source_path)
            shutil.copy2(source_path, destination_path)
            source_after = file_identity(source_path)
            assert_material(source_after, source_before, label=f"copied source {source_path}")
            target = file_identity(destination_path)
            assert_material(
                {key: target[key] for key in ("bytes", "sha256")},
                {key: source_before[key] for key in ("bytes", "sha256")},
                label=f"copied target {destination_path}",
            )

    visit(source, destination)


def _copy_verified_tree(
    source: Path,
    destination: Path,
    expected_source: dict[str, object],
    *,
    exclude_runtime_caches: bool = False,
) -> dict[str, object]:
    assert_material(
        safe_tree(source, exclude_runtime_caches=exclude_runtime_caches),
        expected_source,
        label=f"source before copy {source}",
    )
    destination.mkdir(exist_ok=False)
    _copy_tree_contents(
        source, destination, exclude_runtime_caches=exclude_runtime_caches
    )
    source_after = safe_tree(source, exclude_runtime_caches=exclude_runtime_caches)
    target_after_copy = safe_tree(
        destination, exclude_runtime_caches=exclude_runtime_caches
    )
    assert_material(source_after, expected_source, label=f"source after copy {source}")
    assert_material(target_after_copy, expected_source, label=f"target copy {destination}")
    return {
        "source_path": str(source),
        "target_path": str(destination),
        "source_before": expected_source,
        "source_after": source_after,
        "target_after_copy": target_after_copy,
    }


def _assert_migration_layout(root: Path) -> None:
    entries = sorted(os.scandir(root), key=lambda item: item.name)
    actual: list[str] = []
    for entry in entries:
        path = Path(entry.path)
        info = entry.stat(follow_symlinks=False)
        if entry.is_symlink() or stat_is_reparse_point(info):
            raise RuntimeSealError(f"migration root contains a link/reparse point: {path}")
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeSealError(f"migration root contains a non-domain entry: {path}")
        actual.append(entry.name)
    if set(actual) != set(MIGRATION_DOMAINS) or len(actual) != len(MIGRATION_DOMAINS):
        raise RuntimeSealError(
            f"migration root must contain exactly the reviewed domains: {actual}"
        )


def _named_file_snapshot(root: Path, names: Iterable[str]) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for name in sorted(names):
        path = root / name
        identity = file_identity(path)
        records[name] = identity
    return records


def _toolchain_contract(pyproject_path: Path) -> dict[str, object]:
    pyproject_identity = file_identity(pyproject_path)
    payload = pyproject_path.read_bytes()
    assert_material(
        file_identity(pyproject_path), pyproject_identity, label="pyproject toolchain input"
    )
    document = tomllib.loads(payload.decode("utf-8"))
    requirements = document.get("project", {}).get("dependencies", [])
    if not isinstance(requirements, list) or not requirements:
        raise RuntimeSealError("pyproject has no direct runtime dependencies")
    direct: dict[str, dict[str, str]] = {}
    for requirement in requirements:
        if not isinstance(requirement, str):
            raise RuntimeSealError("pyproject dependency must be a string")
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)", requirement)
        if match is None:
            raise RuntimeSealError(f"cannot parse direct dependency: {requirement}")
        distribution = match.group(1)
        direct[distribution] = {
            "requirement": requirement,
            "installed_version": importlib_metadata.version(distribution),
        }
    runtime = {
        distribution: importlib_metadata.version(distribution)
        for distribution in TOOLCHAIN_RUNTIME_DISTRIBUTIONS
    }
    implementation_version = sys.implementation.version
    executable = Path(sys.executable).resolve(strict=True)
    return {
        "python": {
            "version": sys.version,
            "version_info": list(sys.version_info),
            "implementation": sys.implementation.name,
            "implementation_version": [
                implementation_version.major,
                implementation_version.minor,
                implementation_version.micro,
                implementation_version.releaselevel,
                implementation_version.serial,
            ],
            "cache_tag": sys.implementation.cache_tag,
            "executable": str(executable),
            "executable_identity": file_identity(executable),
        },
        "pyproject": {
            "source_path": str(pyproject_path),
            "identity": pyproject_identity,
        },
        "direct_dependencies": direct,
        "runtime_dependencies": runtime,
    }


def _copy_bound_file(source: Path, destination: Path) -> dict[str, object]:
    before = file_identity(source)
    shutil.copy2(source, destination)
    assert_material(file_identity(source), before, label=f"bound source file {source}")
    target = file_identity(destination)
    assert_material(
        {key: target[key] for key in ("bytes", "sha256")},
        {key: before[key] for key in ("bytes", "sha256")},
        label=f"bound target file {destination}",
    )
    return {"source": before, "target": target, "target_path": str(destination)}


def _copy_runtime_tools(
    source_root: Path,
    destination_root: Path,
    expected: dict[str, dict[str, object]],
) -> dict[str, object]:
    destination_root.mkdir(exist_ok=False)
    for name, before in sorted(expected.items()):
        source = source_root / name
        assert_material(file_identity(source), before, label=f"tool before copy {source}")
        destination = destination_root / name
        shutil.copy2(source, destination)
        assert_material(file_identity(source), before, label=f"tool after copy {source}")
        target = file_identity(destination)
        assert_material(
            {key: target[key] for key in ("bytes", "sha256")},
            {key: before[key] for key in ("bytes", "sha256")},
            label=f"frozen tool {destination}",
        )
    source_tree = _tree_records_identity(expected)
    target_tree = safe_tree(destination_root)
    assert_material(target_tree, source_tree, label="frozen runtime tools")
    return {
        "source_path": str(source_root),
        "target_path": str(destination_root),
        "source_before": expected,
        "source_after": _named_file_snapshot(source_root, expected),
        "target": target_tree,
    }


def _sqlite_uri(path: Path) -> str:
    return f"file:{path.resolve(strict=True).as_posix()}?mode=ro&immutable=1"


def _backup_database(
    source: Path,
    destination: Path,
    expected_source_state: dict[str, object],
) -> dict[str, object]:
    require_no_sqlite_sidecars((source,))
    assert_material(database_state(source), expected_source_state, label=f"database {source}")
    if os.path.lexists(destination):
        raise FileExistsError(f"database target already exists: {destination}")
    with closing(sqlite3.connect(_sqlite_uri(source), uri=True, timeout=30)) as source_db:
        source_db.execute("PRAGMA query_only=ON")
        with closing(sqlite3.connect(destination)) as target_db:
            source_db.backup(target_db)
            target_db.commit()
    require_no_sqlite_sidecars((source, destination))
    assert_material(
        database_state(source), expected_source_state, label=f"database after backup {source}"
    )
    return database_state(destination)


def _normalize_frozen_journal_mode(path: Path) -> None:
    """Make the sealed copy sidecar-free without touching its source database."""

    require_no_sqlite_sidecars((path,))
    with closing(sqlite3.connect(path, timeout=30)) as connection:
        mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
        if mode.casefold() != "delete":
            raise RuntimeSealError(
                f"cannot normalize frozen SQLite journal mode to DELETE: {path}"
            )
        connection.commit()
    require_no_sqlite_sidecars((path,))


def _database_contract(path: Path) -> dict[str, object]:
    # 与 publisher 故障恢复共用 runtime_seal 的逐表规范，禁止同一数据库
    # 在 assembly 和 promotion 阶段出现两种“都叫 content_sha256”的算法。
    return runtime_database_contract(path)


def _logical_database_identity(contract: dict[str, object]) -> dict[str, object]:
    return {
        "migration_versions": contract["migration_versions"],
        "schema_sha256": contract["schema_sha256"],
        "tables": contract["tables"],
    }


def _connection_schema_state(connection: sqlite3.Connection) -> dict[str, object]:
    rows = [
        tuple(str(value or "") for value in row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name"
        )
    ]
    versions = [
        int(row[0])
        for row in connection.execute(
            "SELECT version FROM schema_migration ORDER BY version"
        )
    ]
    return {"migration_versions": versions, "schema_sha256": payload_sha256(rows)}


def _fresh_schema_state(migration_root: Path) -> dict[str, object]:
    safe_tree(migration_root)
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        migrate_up(connection, migration_root)
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = list(connection.execute("PRAGMA foreign_key_check"))
        if integrity != "ok" or foreign_keys:
            raise RuntimeSealError(f"fresh migration replay failed: {migration_root}")
        return _connection_schema_state(connection)


def _assert_schema_replay(
    database_contracts: dict[str, dict[str, object]], frozen_migrations: Path
) -> dict[str, dict[str, object]]:
    replays: dict[str, dict[str, object]] = {}
    for domain in MIGRATION_DOMAINS:
        fresh = _fresh_schema_state(frozen_migrations / domain)
        if domain not in database_contracts:
            replays[domain] = {
                "fresh_schema": fresh,
                "storage_lifecycle": "external_persistent",
            }
            continue
        actual = {
            "migration_versions": database_contracts[domain]["migration_versions"],
            "schema_sha256": database_contracts[domain]["schema_sha256"],
        }
        assert_material(actual, fresh, label=f"fresh schema replay {domain}")
        replays[domain] = fresh
    return replays


def _readonly_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(_sqlite_uri(path), uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _research_update_export_contract(
    database: Path,
    exports_root: Path,
) -> dict[str, object]:
    """Require a drained, DB-derived update history before sealing a candidate."""

    export_files = _safe_file_manifest(exports_root)
    if set(export_files) != {RESEARCH_UPDATE_EXPORT_NAME}:
        raise RuntimeSealError(
            "research update exports must contain only the canonical history JSONL"
        )
    row_manifest = database_row_manifest(
        database,
        include_values_for=RESEARCH_UPDATE_EXPORT_VALUE_TABLES,
    )
    _validate_research_update_projection(row_manifest)
    watermark, history_sha256, row_count = _research_update_export_material(
        row_manifest
    )
    with closing(_readonly_connection(database)) as connection:
        pending = int(
            connection.execute(
                """
                SELECT count(*) FROM outbox_event
                WHERE published_at IS NULL
                  AND event_type IN (
                    'ArchiveResearchUpdateRecorded',
                    'ArchiveResearchUpdateAnnotated'
                  )
                """
            ).fetchone()[0]
        )
        checkpoints = connection.execute(
            """
            SELECT export_name,database_watermark,history_sha256,row_count,exported_at
            FROM research_update_export_checkpoint
            ORDER BY export_name
            """
        ).fetchall()
    if pending:
        raise RuntimeSealError("research update export still has pending outbox events")
    if len(checkpoints) != 1:
        raise RuntimeSealError("research update export requires one exact checkpoint")
    checkpoint = checkpoints[0]
    if (
        str(checkpoint["export_name"]) != RESEARCH_UPDATE_EXPORT_NAME
        or str(checkpoint["database_watermark"]) != watermark
        or str(checkpoint["history_sha256"]) != history_sha256
        or int(checkpoint["row_count"]) != row_count
        or not str(checkpoint["exported_at"]).strip()
    ):
        raise RuntimeSealError(
            "research update export checkpoint differs from database truth"
        )
    export_path = exports_root / RESEARCH_UPDATE_EXPORT_NAME
    descriptor = file_identity(export_path)
    if descriptor.get("sha256") != history_sha256:
        raise RuntimeSealError("research update JSONL differs from database truth")
    return {
        "relative_path": f"exports/{RESEARCH_UPDATE_EXPORT_NAME}",
        "descriptor": descriptor,
        "database_watermark": watermark,
        "history_sha256": history_sha256,
        "row_count": row_count,
        "pending_outbox_events": pending,
        "row_manifest_sha256": payload_sha256(row_manifest),
    }


def _is_lower_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _reviewed_input_descriptor(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"path", "bytes", "sha256"}:
        raise RuntimeSealError(f"{label} must be an exact reviewed file descriptor")
    raw_path = value.get("path")
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path or ":" in raw_path:
        raise RuntimeSealError(f"{label} path is not canonical POSIX form")
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeSealError(f"{label} path escapes its reviewed workspace")
    size = value.get("bytes")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise RuntimeSealError(f"{label} byte count is invalid")
    if not _is_lower_sha256(value.get("sha256")):
        raise RuntimeSealError(f"{label} SHA-256 is invalid")
    return {"path": relative.as_posix(), "bytes": size, "sha256": value["sha256"]}


def _reviewed_gate_receipt_contract(
    research_root: Path, *, expected_material: dict[str, object]
) -> dict[str, object]:
    """Read and validate the replay's independently reviewable total-release receipt."""

    receipt_path = research_root.joinpath(*REVIEWED_GATE_RECEIPT_RELATIVE_PATH.parts)
    try:
        identity_before = file_identity(receipt_path)
        receipt = read_json(receipt_path, schema_version=REVIEWED_GATE_RECEIPT_SCHEMA)
    except FileNotFoundError as error:
        raise RuntimeSealError("reviewed total gate receipt is missing") from error
    identity_after = file_identity(receipt_path)
    assert_material(identity_after, identity_before, label="reviewed total gate receipt read")
    if {
        "bytes": identity_before["bytes"],
        "sha256": identity_before["sha256"],
    } != {
        "bytes": expected_material["receipt_bytes"],
        "sha256": expected_material["receipt_sha256"],
    }:
        raise RuntimeSealError("reviewed total gate receipt identity changed")
    receipt_payload_hash = payload_sha256(receipt)
    if receipt_payload_hash != expected_material["receipt_payload_sha256"]:
        raise RuntimeSealError("reviewed total gate receipt payload changed")

    expected_top_level = {
        "schema_version",
        "fact_boundary",
        "arxiv_independent_gate",
        "arxiv_official_abstract_expectation",
        "crossref_official_abstract_expectation",
        "open_pdf_review_expectation",
        "input_bindings",
        "static_plan_sha256",
        "dedup_expectation",
        "crossref_rights_expectation",
        "release_expectation",
    }
    if set(receipt) != expected_top_level:
        raise RuntimeSealError("reviewed total gate receipt has an unexpected field set")
    if not isinstance(receipt.get("fact_boundary"), str) or not receipt["fact_boundary"].strip():
        raise RuntimeSealError("reviewed total gate receipt omits its fact boundary")
    if receipt.get("static_plan_sha256") != expected_material["static_plan_sha256"]:
        raise RuntimeSealError("reviewed total gate receipt static plan changed")

    arxiv_gate = receipt.get("arxiv_independent_gate")
    if (
        not isinstance(arxiv_gate, dict)
        or arxiv_gate.get("schema_version") != "qrh-independent-arxiv-verdict/v4"
        or arxiv_gate.get("overall_status") != "PASS"
        or arxiv_gate.get("release_authorized") is not True
        or arxiv_gate.get("defects") != []
        or not isinstance(arxiv_gate.get("subject"), dict)
    ):
        raise RuntimeSealError("reviewed total gate receipt lacks the passed arXiv V4 gate")
    arxiv_subject = arxiv_gate["subject"]
    if (
        set(arxiv_subject) != {"path", "schema_version", "bytes", "sha256"}
        or arxiv_subject.get("schema_version") != "qrh-arxiv-expansion-delivery/v1"
        or payload_sha256(arxiv_subject) != expected_material["arxiv_subject_sha256"]
    ):
        raise RuntimeSealError("reviewed arXiv V4 subject binding changed")

    abstract_expectation = receipt.get("arxiv_official_abstract_expectation")
    abstract_expectation_keys = {
        "reviewed_count",
        "total_with_baseline",
        "normalization_contract",
        "projection_sha256",
        "rights_blocked_with_source_evidence",
        "local_pdf_rights_are_independent",
    }
    blocked_with_source_evidence = (
        abstract_expectation.get("rights_blocked_with_source_evidence")
        if isinstance(abstract_expectation, dict)
        else None
    )
    if (
        not isinstance(abstract_expectation, dict)
        or set(abstract_expectation) != abstract_expectation_keys
        or any(
            isinstance(abstract_expectation.get(name), bool)
            or not isinstance(abstract_expectation.get(name), int)
            or abstract_expectation[name] < 0
            for name in ("reviewed_count", "total_with_baseline")
        )
        or abstract_expectation["reviewed_count"]
        > abstract_expectation["total_with_baseline"]
        or not isinstance(abstract_expectation.get("normalization_contract"), str)
        or not abstract_expectation["normalization_contract"].strip()
        or not _is_lower_sha256(abstract_expectation.get("projection_sha256"))
        or not isinstance(blocked_with_source_evidence, list)
        or any(
            not isinstance(item, str) or not item.strip()
            for item in blocked_with_source_evidence
        )
        or len(set(blocked_with_source_evidence)) != len(blocked_with_source_evidence)
        or abstract_expectation.get("local_pdf_rights_are_independent") is not True
        or payload_sha256(abstract_expectation)
        != expected_material["arxiv_official_abstract_expectation_sha256"]
    ):
        raise RuntimeSealError("reviewed official abstract expectation changed")

    crossref_abstract_expectation = receipt.get(
        "crossref_official_abstract_expectation"
    )
    if (
        not isinstance(crossref_abstract_expectation, dict)
        or set(crossref_abstract_expectation)
        != {
            "reviewed_count",
            "normalization_contract",
            "projection_sha256",
            "source_claim_not_fulltext_review",
        }
        or isinstance(crossref_abstract_expectation.get("reviewed_count"), bool)
        or not isinstance(crossref_abstract_expectation.get("reviewed_count"), int)
        or crossref_abstract_expectation["reviewed_count"] < 0
        or not isinstance(
            crossref_abstract_expectation.get("normalization_contract"), str
        )
        or not crossref_abstract_expectation["normalization_contract"].strip()
        or not _is_lower_sha256(
            crossref_abstract_expectation.get("projection_sha256")
        )
        or crossref_abstract_expectation.get(
            "source_claim_not_fulltext_review"
        )
        is not True
        or payload_sha256(crossref_abstract_expectation)
        != expected_material[
            "crossref_official_abstract_expectation_sha256"
        ]
    ):
        raise RuntimeSealError("reviewed Crossref official abstract expectation changed")

    open_pdf_expectation = receipt.get("open_pdf_review_expectation")
    open_pdf_expectation_keys = {
        "schema_version",
        "reviewed_count",
        "allowed_count",
        "fail_closed_count",
        "allowed_projection",
        "allowed_projection_sha256",
        "final_review_sha256",
        "frozen_input_database",
        "independent_verification_sha256",
        "manifest",
        "summary_sha256",
    }
    open_pdf_counts = (
        tuple(
            open_pdf_expectation.get(name)
            for name in ("reviewed_count", "allowed_count", "fail_closed_count")
        )
        if isinstance(open_pdf_expectation, dict)
        else (None, None, None)
    )
    open_pdf_projection = (
        open_pdf_expectation.get("allowed_projection")
        if isinstance(open_pdf_expectation, dict)
        else None
    )
    if (
        not isinstance(open_pdf_expectation, dict)
        or set(open_pdf_expectation) != open_pdf_expectation_keys
        or open_pdf_expectation.get("schema_version")
        != "qrh-reviewed-open-pdf-import/v1"
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in open_pdf_counts
        )
        or open_pdf_counts[0] != open_pdf_counts[1] + open_pdf_counts[2]
        or not _is_lower_sha256(
            open_pdf_expectation.get("allowed_projection_sha256")
        )
        or not isinstance(open_pdf_projection, list)
        or len(open_pdf_projection) != open_pdf_counts[1]
        or payload_sha256(open_pdf_projection)
        != open_pdf_expectation.get("allowed_projection_sha256")
        or not _is_lower_sha256(open_pdf_expectation.get("final_review_sha256"))
        or not _is_lower_sha256(
            open_pdf_expectation.get("independent_verification_sha256")
        )
        or not _is_lower_sha256(open_pdf_expectation.get("summary_sha256"))
        or not isinstance(open_pdf_expectation.get("frozen_input_database"), dict)
        or set(open_pdf_expectation["frozen_input_database"])
        != {"path", "bytes", "sha256"}
        or not isinstance(open_pdf_expectation.get("manifest"), dict)
        or set(open_pdf_expectation["manifest"])
        != {"path", "bytes", "sha256", "covered_files"}
        or payload_sha256(open_pdf_expectation)
        != expected_material["open_pdf_review_expectation_sha256"]
    ):
        raise RuntimeSealError("reviewed open PDF expectation changed")

    bindings = receipt.get("input_bindings")
    expected_binding_keys = {
        "crossref_rights_manifest",
        "crossref_identity_verdicts",
        "crossref_fulltext_manifest",
        "arxiv_materials_manifest",
        "arxiv_reading_records",
        "arxiv_total_delivery_manifest",
        "arxiv_resolution_seed",
        "arxiv_method_origin_inputs",
        "arxiv_independent_verdict",
        "crossref_decisions",
        "dedup_expectation",
        "open_pdf_review_summary",
        "open_pdf_artifact_manifest",
        "open_pdf_independent_verification",
        "open_pdf_final_review",
        "displayable_archive_database",
        "displayable_research_database",
    }
    if not isinstance(bindings, dict) or set(bindings) != expected_binding_keys:
        raise RuntimeSealError("reviewed total gate receipt input binding set is incomplete")
    normalized_bindings: dict[str, object] = {}
    for name, descriptor in bindings.items():
        if name == "crossref_decisions":
            if not isinstance(descriptor, list) or not descriptor:
                raise RuntimeSealError("reviewed Crossref decisions must be a non-empty descriptor list")
            normalized_decisions = [
                _reviewed_input_descriptor(item, label=f"reviewed input {name}")
                for item in descriptor
            ]
            decision_identities = {
                (str(item["path"]), int(item["bytes"]), str(item["sha256"]))
                for item in normalized_decisions
            }
            if len(decision_identities) != len(normalized_decisions):
                raise RuntimeSealError("reviewed Crossref decision descriptors are duplicated")
            normalized_bindings[name] = normalized_decisions
        else:
            normalized_bindings[name] = _reviewed_input_descriptor(
                descriptor, label=f"reviewed input {name}"
            )
    if (
        {
            "path": arxiv_subject["path"],
            "bytes": arxiv_subject["bytes"],
            "sha256": arxiv_subject["sha256"],
        }
        != normalized_bindings["arxiv_total_delivery_manifest"]
        or payload_sha256(normalized_bindings)
        != expected_material["input_bindings_sha256"]
    ):
        raise RuntimeSealError("reviewed input binding identities changed")

    rights = receipt.get("crossref_rights_expectation")
    if (
        not isinstance(rights, dict)
        or set(rights)
        != {
            "rights_ready_without_pdf_bytes",
            "fulltext_failed_closed",
            "rights_manifest",
            "u055_post_get_manifest",
        }
        or rights.get("rights_ready_without_pdf_bytes") != []
        or rights.get("fulltext_failed_closed") != ["U055"]
        or _reviewed_input_descriptor(
            rights.get("rights_manifest"), label="reviewed Crossref rights manifest"
        )
        != normalized_bindings["crossref_rights_manifest"]
        or _reviewed_input_descriptor(
            rights.get("u055_post_get_manifest"), label="reviewed U055 post-GET manifest"
        )
        != normalized_bindings["crossref_fulltext_manifest"]
    ):
        raise RuntimeSealError("reviewed Crossref/U055 failed-closed expectation changed")

    release = receipt.get("release_expectation")
    if not isinstance(release, dict) or set(release) != REVIEWED_RELEASE_EXPECTATION_KEYS:
        raise RuntimeSealError("reviewed total gate receipt release expectation is incomplete")
    normalized_release: dict[str, int] = {}
    for name in sorted(REVIEWED_RELEASE_EXPECTATION_KEYS):
        value = release.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeSealError(f"reviewed release count is invalid: {name}")
        normalized_release[name] = value
    if (
        abstract_expectation["reviewed_count"]
        != normalized_release["reviewed_arxiv_official_abstracts"]
        or abstract_expectation["total_with_baseline"]
        != normalized_release["official_abstract_excerpts"]
        or crossref_abstract_expectation["reviewed_count"]
        != normalized_release["reviewed_crossref_official_abstracts"]
        or open_pdf_expectation["allowed_count"]
        != normalized_release["reviewed_open_pdf_resources"]
    ):
        raise RuntimeSealError(
            "reviewed official abstract expectation and release counts disagree"
        )

    dedup = receipt.get("dedup_expectation")
    expected_counts = dedup.get("expected_counts") if isinstance(dedup, dict) else None
    projection_hashes = dedup.get("projection_hashes") if isinstance(dedup, dict) else None
    expected_dedup_count_keys = {
        "baseline",
        "crossref_incoming",
        "arxiv_incoming",
        "formal_citation_incoming",
        "associated_method_origin_incoming",
        "incoming",
        "incoming_unique_identity_keys",
        "incoming_baseline_overlap",
        "created_new_canonical",
        "reused_baseline",
        "reused_incoming",
        "canonical_total",
    }
    expected_projection_keys = {
        "projection_encoding",
        "baseline_identity_keys_lf_sha256",
        "incoming_identity_keys_lf_sha256",
        "union_identity_keys_lf_sha256",
        "incoming_action_tsv",
    }
    if (
        not isinstance(dedup, dict)
        or dedup.get("schema_version") != "qrh-reviewed-evidence-dedup-expectation/v1"
        or not isinstance(expected_counts, dict)
        or set(expected_counts) != expected_dedup_count_keys
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in expected_counts.values()
        )
        or expected_counts["incoming"]
        != expected_counts["crossref_incoming"] + expected_counts["arxiv_incoming"]
        or expected_counts["incoming"]
        != expected_counts["formal_citation_incoming"]
        + expected_counts["associated_method_origin_incoming"]
        or expected_counts["incoming_unique_identity_keys"] != expected_counts["incoming"]
        or expected_counts["incoming_baseline_overlap"] != 0
        or expected_counts["created_new_canonical"] != expected_counts["incoming"]
        or expected_counts["reused_baseline"] != 0
        or expected_counts["reused_incoming"] != 0
        or expected_counts["canonical_total"]
        != expected_counts["baseline"] + expected_counts["created_new_canonical"]
        or expected_counts.get("canonical_total") != normalized_release["canonical_papers"]
        or expected_counts.get("incoming") != normalized_release["canonicalization_receipts"]
        or expected_counts.get("formal_citation_incoming") != normalized_release["formal_receipts"]
        or expected_counts.get("associated_method_origin_incoming")
        != normalized_release["method_receipts"]
    ):
        raise RuntimeSealError("reviewed dedup expectation and release expectation disagree")
    action_projection = (
        projection_hashes.get("incoming_action_tsv")
        if isinstance(projection_hashes, dict)
        else None
    )
    if (
        not isinstance(projection_hashes, dict)
        or set(projection_hashes) != expected_projection_keys
        or projection_hashes.get("projection_encoding")
        != "UTF-8 without BOM, LF terminated, StringComparer.Ordinal line ordering"
        or any(
            not _is_lower_sha256(projection_hashes.get(name))
            for name in (
                "baseline_identity_keys_lf_sha256",
                "incoming_identity_keys_lf_sha256",
                "union_identity_keys_lf_sha256",
            )
        )
        or not isinstance(action_projection, dict)
        or set(action_projection) != {"columns", "rows", "bytes", "sha256"}
        or action_projection.get("columns")
        != [
            "source_system",
            "source_candidate_id",
            "paper_source_candidate_id",
            "treatment",
            "identity_key",
            "expected_action",
            "expected_target_identity_key",
        ]
        or action_projection.get("rows") != expected_counts["incoming"]
        or isinstance(action_projection.get("bytes"), bool)
        or not isinstance(action_projection.get("bytes"), int)
        or action_projection["bytes"] < 0
        or not _is_lower_sha256(action_projection.get("sha256"))
        or payload_sha256(dedup) != expected_material["dedup_expectation_sha256"]
    ):
        raise RuntimeSealError("reviewed dedup projection seal changed")

    descriptor = {
        "relative_path": REVIEWED_GATE_RECEIPT_RELATIVE_PATH.as_posix(),
        "bytes": identity_before["bytes"],
        "sha256": identity_before["sha256"],
    }
    return {
        "schema_version": REVIEWED_GATE_RECEIPT_SCHEMA,
        "descriptor": descriptor,
        "source_identity": identity_before,
        "receipt_payload_sha256": receipt_payload_hash,
        "input_bindings_sha256": payload_sha256(normalized_bindings),
        "dedup_expectation_sha256": payload_sha256(dedup),
        "release_expectation": normalized_release,
        "official_abstract_expectation": abstract_expectation,
        "crossref_official_abstract_expectation": crossref_abstract_expectation,
        "open_pdf_review_expectation": open_pdf_expectation,
        "upstream_gate": {
            "arxiv_schema_version": arxiv_gate["schema_version"],
            "arxiv_overall_status": arxiv_gate["overall_status"],
            "arxiv_release_authorized": arxiv_gate["release_authorized"],
            "crossref_rights_ready_without_pdf_bytes": [],
            "crossref_fulltext_failed_closed": ["U055"],
        },
    }


def _evidence_counts(database: Path) -> dict[str, int]:
    queries = {
        "canonical_papers": "SELECT count(*) FROM paper",
        "verified_resources": (
            "SELECT count(*) FROM paper_resource WHERE verification_status='verified'"
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
    with closing(_readonly_connection(database)) as connection:
        return {
            name: int(connection.execute(query).fetchone()[0])
            for name, query in queries.items()
        }


def _reviewed_chinese_overlay_contract(
    database: Path,
    overlay_path: Path,
    expected_entries: int,
    *,
    synthetic_test_mode: bool,
) -> dict[str, object]:
    if synthetic_test_mode and expected_entries == 0:
        return {
            "schema_version": OVERLAY_SCHEMA,
            "status": "not_applicable_no_official_abstracts",
            "entries": 0,
            "excluded": 0,
            "database_official_abstracts": 0,
        }
    try:
        contract = build_chinese_overlay_contract(database, overlay_path)
    except ChineseOverlayContractError as error:
        raise RuntimeSealError(f"正式中文展示层未通过装配门禁：{error}") from error
    if (
        contract["entries"] != expected_entries
        or contract["database_official_abstracts"] != expected_entries
    ):
        raise RuntimeSealError("正式中文展示层覆盖数与审核收据不一致")
    return contract


def _paper_lab_count(database: Path) -> int:
    with closing(_readonly_connection(database)) as connection:
        return int(connection.execute("SELECT count(*) FROM lab_paper").fetchone()[0])


def _canonical_resource_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or ":" in value:
        raise RuntimeSealError("Evidence resource path is not canonical POSIX form")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or not relative.parts
        or relative.parts[0] != "objects"
    ):
        raise RuntimeSealError("Evidence resource path escapes research_papers/objects")
    return relative


def _resource_contract(research_root: Path, database: Path) -> dict[str, object]:
    objects = research_root / "objects"
    _real_directory(objects, label="research_papers objects")
    objects_tree_before = safe_tree(objects)
    object_files = _safe_file_manifest(objects)
    actual_paths = {f"objects/{relative}" for relative in object_files}
    rows: list[dict[str, object]] = []
    sealed_items: list[dict[str, object]] = []
    with closing(_readonly_connection(database)) as connection:
        for row in connection.execute(
            "SELECT resource_id,relative_path,content_sha256,bytes,media_type,"
            "verification_status,rights_status FROM paper_resource ORDER BY resource_id"
        ):
            relative = _canonical_resource_path(str(row["relative_path"]))
            canonical = relative.as_posix()
            target = research_root.joinpath(*relative.parts)
            identity = file_identity(target)
            expected = {
                "bytes": int(row["bytes"]),
                "sha256": str(row["content_sha256"]),
            }
            assert_material(
                {key: identity[key] for key in ("bytes", "sha256")},
                expected,
                label=f"Evidence resource {row['resource_id']}",
            )
            if str(row["verification_status"]) != "verified":
                raise RuntimeSealError("locally stored paper_resource is not verified")
            if str(row["media_type"]) != "application/pdf":
                raise RuntimeSealError("locally stored paper_resource is not a PDF")
            with target.open("rb") as handle:
                if handle.read(5) != b"%PDF-":
                    raise RuntimeSealError(
                        f"verified PDF has invalid magic: {row['resource_id']}"
                    )
            rows.append(
                {
                    "resource_id": str(row["resource_id"]),
                    "relative_path": canonical,
                    **expected,
                    "media_type": str(row["media_type"]),
                    "verification_status": str(row["verification_status"]),
                    "rights_status": str(row["rights_status"]),
                }
            )
            sealed_items.append(
                {
                    "resource_id": str(row["resource_id"]),
                    "relative_path": canonical,
                    **expected,
                }
            )
    database_paths = {str(item["relative_path"]) for item in rows}
    missing = sorted(database_paths - actual_paths)
    orphaned = sorted(actual_paths - database_paths)
    if missing or orphaned:
        raise RuntimeSealError(
            "research_papers resource closure failed: "
            f"missing={missing[:5]}, orphaned={orphaned[:5]}"
        )
    objects_tree_after = safe_tree(objects)
    assert_material(objects_tree_after, objects_tree_before, label="Evidence objects tree")
    return {
        "sealed_contract": {
            "resources": len(sealed_items),
            "items_sha256": hashlib.sha256(
                canonical_json(sealed_items).encode("utf-8")
            ).hexdigest(),
            "objects": objects_tree_after,
        },
        "audit": {
            "database_resources": len(rows),
            "object_files": len(actual_paths),
            "verified_resources": len(sealed_items),
            "resources_sha256": payload_sha256(rows),
            "objects_tree": objects_tree_after,
            "missing_paths": [],
            "orphaned_paths": [],
        },
    }


def _prepare_evidence_candidate(settings: Settings) -> PreparedEvidenceRelease:
    return EvidenceReleaseService(settings).prepare_candidate()


def _prepared_inventory_contract(
    prepared: PreparedEvidenceRelease, research_root: Path
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, inventory in (
        ("inventory", prepared.inventory),
        ("candidate_inventory", prepared.candidate_inventory),
    ):
        relative = _canonical_resource_like_export_path(inventory.relative_path)
        target = research_root.joinpath(*relative.parts)
        identity = file_identity(target)
        expected = {"bytes": inventory.bytes, "sha256": inventory.content_sha256}
        assert_material(
            {key: identity[key] for key in ("bytes", "sha256")},
            expected,
            label=f"prepared {name}",
        )
        result[name] = {**asdict(inventory), "file_identity": identity}
    return result


def _canonical_resource_like_export_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or ":" in value:
        raise RuntimeSealError("inventory export path is not canonical POSIX form")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or not relative.parts
        or relative.parts[0] != "exports"
    ):
        raise RuntimeSealError("inventory export escapes research_papers/exports")
    return relative


def _tree_delta(
    before: dict[str, dict[str, object]], after: dict[str, dict[str, object]]
) -> dict[str, list[str]]:
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(
            key for key in set(before) & set(after) if before[key] != after[key]
        ),
    }


def _table_delta(
    before: dict[str, dict[str, object]], after: dict[str, dict[str, object]]
) -> list[str]:
    return sorted(
        name
        for name in set(before) | set(after)
        if before.get(name) != after.get(name)
    )


def _ensure_new_directory(path: Path) -> None:
    if os.path.lexists(path):
        raise FileExistsError(path)
    path.mkdir(exist_ok=False)
    _real_directory(path, label="new assembly output")


def _ensure_report_parent(report: Path, gates_root: Path) -> None:
    relative = report.parent.relative_to(gates_root)
    current = gates_root
    for part in relative.parts:
        current = current / part
        if os.path.lexists(current):
            _real_directory(current, label="gate report directory")
        else:
            current.mkdir(exist_ok=False)
            _real_directory(current, label="gate report directory")


def assemble_delivery(
    *,
    source_delivery_var: Path,
    evidence_candidate_var: Path,
    output_var: Path,
    report: Path,
    minimum_evidence_papers: int,
    minimum_evidence_resources: int,
    expected_paper_lab_papers: int = 137,
    expected_reviewed_release: dict[str, int] | None = None,
    expected_reviewed_gate_material: dict[str, object] | None = None,
    workspace_root: Path = WORKSPACE_ROOT,
    formal_root: Path = FORMAL_ROOT,
    prepare_candidate: Callable[[Settings], PreparedEvidenceRelease] = _prepare_evidence_candidate,
    execution_material_paths: dict[str, Path] | None = None,
    synthetic_test_mode: bool = False,
) -> dict[str, object]:
    if min(
        minimum_evidence_papers,
        minimum_evidence_resources,
        expected_paper_lab_papers,
    ) < 0:
        raise ValueError("minimum counts and expected Paper Lab count must be non-negative")
    injected_contracts = (
        expected_reviewed_release is not None
        or expected_reviewed_gate_material is not None
        or prepare_candidate is not _prepare_evidence_candidate
        or execution_material_paths is not None
    )
    if synthetic_test_mode:
        if (
            not injected_contracts
            or workspace_root.resolve() == WORKSPACE_ROOT.resolve()
            or formal_root.resolve() == FORMAL_ROOT.resolve()
        ):
            raise ValueError(
                "synthetic test mode requires injected contracts and isolated roots"
            )
    elif injected_contracts:
        raise ValueError(
            "reviewed contract injection is forbidden outside isolated synthetic tests"
        )
    selected_reviewed_release = dict(
        REVIEWED_RELEASE_EXPECTATION
        if expected_reviewed_release is None
        else expected_reviewed_release
    )
    if (
        set(selected_reviewed_release) != REVIEWED_RELEASE_EXPECTATION_KEYS
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in selected_reviewed_release.values()
        )
    ):
        raise ValueError("expected reviewed release must contain the exact non-negative count set")
    selected_gate_material = dict(
        REVIEWED_GATE_MATERIAL
        if expected_reviewed_gate_material is None
        else expected_reviewed_gate_material
    )
    expected_gate_material_keys = {
        "receipt_bytes",
        "receipt_sha256",
        "receipt_payload_sha256",
        "input_bindings_sha256",
        "dedup_expectation_sha256",
        "arxiv_subject_sha256",
        "arxiv_official_abstract_expectation_sha256",
        "crossref_official_abstract_expectation_sha256",
        "open_pdf_review_expectation_sha256",
        "static_plan_sha256",
    }
    if (
        set(selected_gate_material) != expected_gate_material_keys
        or isinstance(selected_gate_material.get("receipt_bytes"), bool)
        or not isinstance(selected_gate_material.get("receipt_bytes"), int)
        or selected_gate_material["receipt_bytes"] <= 0
        or any(
            not _is_lower_sha256(selected_gate_material.get(name))
            for name in expected_gate_material_keys - {"receipt_bytes"}
        )
    ):
        raise ValueError("expected reviewed gate material is incomplete or invalid")
    paths = _resolve_paths(
        source_delivery_var=source_delivery_var,
        evidence_candidate_var=evidence_candidate_var,
        output_var=output_var,
        report=report,
        workspace_root=workspace_root,
        formal_root=formal_root,
    )
    using_default_execution_materials = execution_material_paths is None
    selected_execution_materials = execution_material_paths or {
        "assembler": ASSEMBLER_PATH,
        "runtime_seal": RUNTIME_SEAL_MODULE_PATH,
        "pyproject": PYPROJECT_PATH,
    }
    if set(selected_execution_materials) != {
        "assembler",
        "runtime_seal",
        "pyproject",
    }:
        raise RuntimeSealError("execution material set is incomplete")
    execution_materials_before: dict[str, dict[str, object]] = {}
    for name, selected in selected_execution_materials.items():
        path = selected.resolve(strict=True)
        if not path.is_relative_to(paths.workspace):
            raise RuntimeSealError(f"execution material is outside workspace: {path}")
        current_identity = file_identity(path)
        if using_default_execution_materials:
            assert_material(
                current_identity,
                DEFAULT_EXECUTION_IDENTITIES_AT_IMPORT[name],
                label=f"execution material since import {name}",
            )
        execution_materials_before[name] = {
            "path": str(path),
            "identity": current_identity,
            **(
                {"import_identity": DEFAULT_EXECUTION_IDENTITIES_AT_IMPORT[name]}
                if using_default_execution_materials
                else {}
            ),
        }

    source_integrity_before = {
        "archive": safe_tree(paths.archive),
        "proj2": safe_tree(paths.proj2),
    }
    managed_sources = {
        name: paths.source_delivery / name for name in SOURCE_MANAGED_TREES
    }
    managed_sources["research_papers"] = paths.evidence_candidate / "research_papers"
    # Settings.ensure_runtime_directories 不得在 prepare 阶段悄悄补建候选结构。
    for required in (
        paths.source_delivery / "objects",
        paths.source_delivery / "paper_lab" / "assets",
        paths.source_delivery / "replay" / "evidence",
        paths.evidence_candidate / "research_papers" / "objects",
        paths.evidence_candidate / "research_papers" / "exports",
        paths.workspace / "quant_hub" / "paper_lab" / "papers",
    ):
        _real_directory(required, label="required managed directory")
    managed_before = {name: safe_tree(path) for name, path in managed_sources.items()}
    reviewed_gate_receipt_before = _reviewed_gate_receipt_contract(
        managed_sources["research_papers"], expected_material=selected_gate_material
    )
    if reviewed_gate_receipt_before["release_expectation"] != selected_reviewed_release:
        raise RuntimeSealError(
            "reviewed total gate receipt does not match the assembly release expectation"
        )
    for source in managed_sources.values():
        _reject_reserved_seal_name(source)

    migration_source = paths.formal_root / "migrations"
    code_source = paths.formal_root / "src" / "quant_hub"
    tools_source = paths.formal_root / "tools"
    pyproject_source = paths.formal_root / "pyproject.toml"
    _assert_migration_layout(migration_source)
    _reject_reserved_seal_name(migration_source)
    _reject_reserved_seal_name(code_source, exclude_runtime_caches=True)
    migration_before = safe_tree(migration_source)
    migration_domains_before = {
        domain: safe_tree(migration_source / domain) for domain in MIGRATION_DOMAINS
    }
    code_before = safe_tree(code_source, exclude_runtime_caches=True)
    loaded_package_root = Path(sys.modules["quant_hub"].__file__).resolve(strict=True).parent
    loaded_code_before = safe_tree(
        loaded_package_root, exclude_runtime_caches=True
    )
    assert_material(
        loaded_code_before,
        code_before,
        label="loaded implementation versus frozen runtime source",
    )
    tools_before = _named_file_snapshot(tools_source, RUNTIME_TOOLS)
    toolchain_before = _toolchain_contract(pyproject_source)
    sealed_toolchain_before = runtime_toolchain()

    database_sources = {
        "platform": paths.source_delivery / "db" / DATABASE_FILES["platform"],
        "archive": paths.source_delivery / "db" / DATABASE_FILES["archive"],
        "research_papers": (
            paths.evidence_candidate / "db" / DATABASE_FILES["research_papers"]
        ),
        "paper_lab": paths.source_delivery / "db" / DATABASE_FILES["paper_lab"],
    }
    require_no_sqlite_sidecars(database_sources.values())
    database_sources_before = {
        domain: database_state(path) for domain, path in database_sources.items()
    }
    database_source_contracts = {
        domain: _database_contract(path) for domain, path in database_sources.items()
    }
    for domain in DATABASE_FILES:
        assert_material(
            {
                key: database_source_contracts[domain][key]
                for key in database_sources_before[domain]
            },
            database_sources_before[domain],
            label=f"source database contract {domain}",
        )
    source_update_export_contract = _research_update_export_contract(
        database_sources["archive"],
        managed_sources["exports"],
    )

    _ensure_new_directory(paths.output)
    managed_contracts: dict[str, dict[str, object]] = {}
    for name in SOURCE_MANAGED_TREES:
        managed_contracts[name] = _copy_verified_tree(
            managed_sources[name], paths.output / name, managed_before[name]
        )
    managed_contracts["research_papers"] = _copy_verified_tree(
        managed_sources["research_papers"],
        paths.output / "research_papers",
        managed_before["research_papers"],
    )

    runtime_contract_root = paths.output / "runtime_contract"
    runtime_contract_root.mkdir(exist_ok=False)
    frozen_migrations = runtime_contract_root / "migrations"
    migration_contract = _copy_verified_tree(
        migration_source, frozen_migrations, migration_before
    )
    frozen_code_root = runtime_contract_root / "code"
    frozen_code_root.mkdir(exist_ok=False)
    frozen_package = frozen_code_root / "src" / "quant_hub"
    frozen_package.parent.mkdir(exist_ok=False)
    code_contract = _copy_verified_tree(
        code_source,
        frozen_package,
        code_before,
        exclude_runtime_caches=True,
    )
    tools_contract = _copy_runtime_tools(
        tools_source, frozen_code_root / "tools", tools_before
    )
    frozen_pyproject = _copy_bound_file(
        pyproject_source, frozen_code_root / "pyproject.toml"
    )

    database_root = paths.output / "db"
    database_root.mkdir(exist_ok=False)
    initial_database_contracts: dict[str, dict[str, object]] = {}
    for domain, source in database_sources.items():
        destination = database_root / DATABASE_FILES[domain]
        _backup_database(source, destination, database_sources_before[domain])
        _normalize_frozen_journal_mode(destination)
        initial_database_contracts[domain] = _database_contract(destination)
        assert_material(
            _logical_database_identity(initial_database_contracts[domain]),
            _logical_database_identity(database_source_contracts[domain]),
            label=f"SQLite backup logical identity {domain}",
        )
    target_update_export_contract = _research_update_export_contract(
        database_root / DATABASE_FILES["archive"],
        paths.output / "exports",
    )
    for field in (
        "database_watermark",
        "history_sha256",
        "row_count",
        "pending_outbox_events",
        "row_manifest_sha256",
    ):
        if target_update_export_contract[field] != source_update_export_contract[field]:
            raise RuntimeSealError(
                "sealed research update export differs from its source database"
            )

    schema_replays = _assert_schema_replay(
        initial_database_contracts, frozen_migrations
    )
    settings = Settings.default(
        project_root=paths.workspace,
        archive_root=paths.archive,
        var_root=paths.output,
        migration_root=frozen_migrations / "platform",
    )
    settings.validate_reviewed_runtime()

    research_tree_before_prepare = _safe_file_manifest(
        paths.output / "research_papers"
    )
    evidence_tables_before_prepare = initial_database_contracts["research_papers"][
        "tables"
    ]
    prepared = prepare_candidate(settings)
    if not isinstance(prepared, PreparedEvidenceRelease):
        raise RuntimeSealError("prepare_candidate returned an unexpected result")
    inventory_contract = _prepared_inventory_contract(
        prepared, paths.output / "research_papers"
    )
    service_snapshot = EvidenceReleaseService(settings).repository.snapshot_hash()
    assert_material(
        service_snapshot,
        prepared.candidate_spec.source_snapshot_hash,
        label="prepared Evidence repository snapshot",
    )
    assert_material(
        safe_tree(loaded_package_root, exclude_runtime_caches=True),
        loaded_code_before,
        label="loaded implementation after Evidence preparation",
    )
    require_no_sqlite_sidecars(
        database_root / filename for filename in DATABASE_FILES.values()
    )
    # Evidence preparation opens its repository through the normal writable
    # connection policy, which can persist WAL mode even after all handles are
    # closed.  Re-normalize every frozen database only after that final
    # preparation step so the sealed runtime never needs writable sidecars.
    for filename in DATABASE_FILES.values():
        _normalize_frozen_journal_mode(database_root / filename)

    final_database_contracts = {
        domain: _database_contract(database_root / DATABASE_FILES[domain])
        for domain in DATABASE_FILES
    }
    # prepare_candidate 只能写 inventory registry 与 staging release 闭集。
    changed_tables = _table_delta(
        evidence_tables_before_prepare,
        final_database_contracts["research_papers"]["tables"],
    )
    unexpected_tables = sorted(set(changed_tables) - PREPARE_MUTABLE_TABLES)
    if unexpected_tables:
        raise RuntimeSealError(
            f"prepare_candidate changed tables outside its closed set: {unexpected_tables}"
        )
    for domain in ("platform", "archive", "paper_lab"):
        assert_material(
            final_database_contracts[domain],
            initial_database_contracts[domain],
            label=f"database changed during Evidence preparation: {domain}",
        )
    _assert_schema_replay(final_database_contracts, frozen_migrations)

    research_tree_after_prepare = _safe_file_manifest(
        paths.output / "research_papers"
    )
    research_delta = _tree_delta(
        research_tree_before_prepare, research_tree_after_prepare
    )
    allowed_export_paths = {
        prepared.inventory.relative_path,
        prepared.candidate_inventory.relative_path,
    }
    if (
        research_delta["removed"]
        or research_delta["changed"]
        or set(research_delta["added"]) - allowed_export_paths
    ):
        raise RuntimeSealError(
            f"prepare_candidate changed research_papers outside inventory exports: {research_delta}"
        )

    evidence_counts = _evidence_counts(settings.research_papers_database_path)
    evidence_query = EvidenceQueryService(settings)
    listed_papers = evidence_query.list_papers(limit=500)["papers"]
    paper_details = [
        evidence_query.paper_detail(str(paper["paper_id"])) for paper in listed_papers
    ]
    # The reviewed receipt records the frozen V4 Archive projection.  Archive is
    # independently versioned and may legitimately replace its current document
    # paths, so replay that historical count from the hash-bound receipt and
    # measure both current exact-path and effective public coverage separately.
    # Coupling the immutable Evidence release back to today's Archive projection
    # would make every valid research-document update invalidate the paper corpus.
    release_expectation = reviewed_gate_receipt_before["release_expectation"]
    paper_ids = {str(paper["paper_id"]) for paper in listed_papers}
    paper_titles = {
        str(paper["paper_id"]): str(paper.get("title") or "")
        for paper in listed_papers
    }
    with closing(_readonly_connection(settings.research_papers_database_path)) as connection:
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
    evidence_counts["displayable_archive_relation_papers"] = int(
        release_expectation["displayable_archive_relation_papers"]
    )
    evidence_counts["current_exact_archive_relation_papers"] = (
        legacy_current_coverage
    )
    evidence_counts["effective_displayable_archive_relation_papers"] = sum(
        bool(detail["evidence_coverage"]["archive_relations"])
        for detail in paper_details
    )
    # The public query service intentionally uses the normal runtime connection
    # path.  Its first read can persist SQLite's WAL journal mode in both the
    # Evidence and Archive database headers even though no logical row changes.
    # Capture the post-query identities here to prove that this read path did
    # not alter any schema, migration, or table projection.  Final sidecar-free
    # byte identities are normalized after every database-backed review below.
    require_no_sqlite_sidecars(
        database_root / filename for filename in DATABASE_FILES.values()
    )
    post_display_database_contracts = {
        domain: _database_contract(database_root / DATABASE_FILES[domain])
        for domain in DATABASE_FILES
    }
    for domain in DATABASE_FILES:
        assert_material(
            _logical_database_identity(post_display_database_contracts[domain]),
            _logical_database_identity(final_database_contracts[domain]),
            label=f"displayable relation query logical database {domain}",
        )
    final_database_contracts = post_display_database_contracts
    final_update_export_contract = _research_update_export_contract(
        database_root / DATABASE_FILES["archive"],
        paths.output / "exports",
    )
    assert_material(
        final_update_export_contract,
        target_update_export_contract,
        label="research update export after candidate preparation",
    )
    if evidence_counts["canonical_papers"] < minimum_evidence_papers:
        raise RuntimeSealError("assembled candidate has fewer canonical papers than reviewed")
    if evidence_counts["verified_resources"] < minimum_evidence_resources:
        raise RuntimeSealError("assembled candidate has fewer verified resources than reviewed")
    observed_reviewed_release = {
        name: evidence_counts[name] for name in REVIEWED_RELEASE_EXPECTATION_KEYS
    }
    if observed_reviewed_release != release_expectation:
        raise RuntimeSealError(
            "assembled Evidence counts differ from the reviewed total gate receipt"
        )
    try:
        official_abstract_projection_contract = (
            build_reviewed_arxiv_official_abstract_projection_contract(
                settings.research_papers_database_path
            )
        )
    except ChineseOverlayContractError as error:
        raise RuntimeSealError(
            f"reviewed arXiv 官方摘要投影无法从候选重建：{error}"
        ) from error
    official_abstract_expectation = reviewed_gate_receipt_before[
        "official_abstract_expectation"
    ]
    if (
        official_abstract_projection_contract["rows"]
        != release_expectation["reviewed_arxiv_official_abstracts"]
        or official_abstract_projection_contract["projection_sha256"]
        != official_abstract_expectation["projection_sha256"]
    ):
        raise RuntimeSealError(
            "reviewed arXiv 官方摘要投影与审核收据不一致"
        )
    try:
        crossref_official_abstract_projection_contract = (
            build_reviewed_crossref_official_abstract_projection_contract(
                settings.research_papers_database_path
            )
        )
    except ChineseOverlayContractError as error:
        raise RuntimeSealError(
            f"reviewed Crossref 官方摘要投影无法从候选重建：{error}"
        ) from error
    crossref_official_abstract_expectation = reviewed_gate_receipt_before[
        "crossref_official_abstract_expectation"
    ]
    if (
        crossref_official_abstract_projection_contract["rows"]
        != release_expectation["reviewed_crossref_official_abstracts"]
        or crossref_official_abstract_projection_contract["projection_sha256"]
        != crossref_official_abstract_expectation["projection_sha256"]
    ):
        raise RuntimeSealError(
            "reviewed Crossref 官方摘要投影与审核收据不一致"
        )
    overlay_path = frozen_package / "presentation" / "evidence_zh_overlays.json"
    chinese_overlay_contract = _reviewed_chinese_overlay_contract(
        settings.research_papers_database_path,
        overlay_path,
        release_expectation["official_abstract_excerpts"],
        synthetic_test_mode=synthetic_test_mode,
    )
    paper_lab_papers = _paper_lab_count(settings.paper_lab_database_path)
    if paper_lab_papers != expected_paper_lab_papers:
        raise RuntimeSealError(
            f"Paper Lab parity changed: {paper_lab_papers} != {expected_paper_lab_papers}"
        )
    resource_contract = _resource_contract(
        settings.research_papers_root, settings.research_papers_database_path
    )
    if (
        resource_contract["audit"]["verified_resources"]
        != release_expectation["verified_resources"]
    ):
        raise RuntimeSealError(
            "Evidence resource closure differs from the reviewed total gate receipt"
        )
    require_no_sqlite_sidecars(
        database_root / filename for filename in DATABASE_FILES.values()
    )
    for filename in DATABASE_FILES.values():
        _normalize_frozen_journal_mode(database_root / filename)
    sealed_database_contracts = {
        domain: _database_contract(database_root / DATABASE_FILES[domain])
        for domain in DATABASE_FILES
    }
    for domain in DATABASE_FILES:
        assert_material(
            _logical_database_identity(sealed_database_contracts[domain]),
            _logical_database_identity(final_database_contracts[domain]),
            label=f"final journal normalization logical database {domain}",
        )
    final_database_contracts = sealed_database_contracts

    # 所有输入在整个组装窗口内都必须保持原身份；目标的初始复制也必须与输入相等。
    for name, source in managed_sources.items():
        assert_material(
            safe_tree(source), managed_before[name], label=f"managed source final {name}"
        )
        managed_contracts[name]["source_final"] = managed_before[name]
        sealed_target = safe_tree(paths.output / name)
        if name != "research_papers":
            assert_material(
                sealed_target, managed_before[name], label=f"managed target final {name}"
            )
        managed_contracts[name]["sealed_target"] = sealed_target
        managed_contracts[name]["sealed_tree"] = sealed_target
    managed_contracts["research_papers"]["authorized_prepare_delta"] = research_delta

    reviewed_gate_receipt_final = _reviewed_gate_receipt_contract(
        managed_sources["research_papers"], expected_material=selected_gate_material
    )
    assert_material(
        reviewed_gate_receipt_final,
        reviewed_gate_receipt_before,
        label="reviewed total gate receipt final source",
    )
    reviewed_gate_receipt_target = _reviewed_gate_receipt_contract(
        paths.output / "research_papers", expected_material=selected_gate_material
    )
    if (
        reviewed_gate_receipt_target["descriptor"]
        != reviewed_gate_receipt_before["descriptor"]
        or reviewed_gate_receipt_target["receipt_payload_sha256"]
        != reviewed_gate_receipt_before["receipt_payload_sha256"]
        or reviewed_gate_receipt_target["release_expectation"]
        != release_expectation
    ):
        raise RuntimeSealError("sealed reviewed total gate receipt differs from its source")
    reviewed_gate_receipt_contract = {
        **reviewed_gate_receipt_before,
        "sealed_target": reviewed_gate_receipt_target["descriptor"],
    }
    resource_contract["reviewed_gate_receipt"] = reviewed_gate_receipt_contract

    assert_material(safe_tree(migration_source), migration_before, label="migration source final")
    assert_material(
        safe_tree(frozen_migrations), migration_before, label="frozen migrations final"
    )
    assert_material(
        safe_tree(code_source, exclude_runtime_caches=True),
        code_before,
        label="runtime source final",
    )
    assert_material(
        safe_tree(frozen_package, exclude_runtime_caches=True),
        code_before,
        label="frozen runtime code final",
    )
    assert_material(
        _named_file_snapshot(tools_source, tools_before),
        tools_before,
        label="runtime tools final",
    )
    toolchain_final = _toolchain_contract(pyproject_source)
    assert_material(toolchain_final, toolchain_before, label="runtime toolchain final")
    sealed_toolchain_final = runtime_toolchain()
    assert_material(
        sealed_toolchain_final,
        sealed_toolchain_before,
        label="sealed runtime toolchain final",
    )
    assert_material(
        file_identity(frozen_code_root / "pyproject.toml"),
        frozen_pyproject["target"],
        label="frozen pyproject final",
    )
    execution_materials_final: dict[str, dict[str, object]] = {}
    for name, before in execution_materials_before.items():
        path = Path(str(before["path"]))
        final_identity = file_identity(path)
        assert_material(
            final_identity,
            before["identity"],
            label=f"execution material final {name}",
        )
        execution_materials_final[name] = {
            **before,
            "final_identity": final_identity,
        }
    frozen_runtime_seal = file_identity(frozen_package / "runtime_seal.py")
    assert_material(
        {key: frozen_runtime_seal[key] for key in ("bytes", "sha256")},
        {
            key: execution_materials_before["runtime_seal"]["identity"][key]
            for key in ("bytes", "sha256")
        },
        label="loaded versus frozen runtime_seal",
    )
    execution_materials_final["runtime_seal"]["frozen_target"] = {
        "path": str(frozen_package / "runtime_seal.py"),
        "identity": frozen_runtime_seal,
    }
    execution_materials_final["pyproject"]["frozen_target"] = {
        "path": str(frozen_code_root / "pyproject.toml"),
        "identity": frozen_pyproject["target"],
    }
    require_no_sqlite_sidecars(database_sources.values())
    for domain, source in database_sources.items():
        assert_material(
            database_state(source),
            database_sources_before[domain],
            label=f"source database final {domain}",
        )
    source_integrity_after = {
        "archive": safe_tree(paths.archive),
        "proj2": safe_tree(paths.proj2),
    }
    assert_material(
        source_integrity_after, source_integrity_before, label="read-only source integrity"
    )

    for domain in MIGRATION_DOMAINS:
        assert_material(
            safe_tree(frozen_migrations / domain),
            migration_domains_before[domain],
            label=f"frozen migration domain {domain}",
        )
    migration_contract["domains"] = migration_domains_before
    migration_contract["sealed_tree"] = safe_tree(frozen_migrations)
    code_contract["sealed_target"] = safe_tree(
        frozen_package, exclude_runtime_caches=True
    )
    code_contract["sealed_tree"] = safe_tree(
        frozen_code_root, exclude_runtime_caches=True
    )
    code_contract["loaded_implementation"] = {
        "path": str(loaded_package_root),
        "tree": loaded_code_before,
    }
    tools_contract["source_final"] = _named_file_snapshot(tools_source, tools_before)

    databases = {
        domain: {
            "relative_path": f"db/{DATABASE_FILES[domain]}",
            "database_contract": final_database_contracts[domain],
            "database_contract_sha256": payload_sha256(
                final_database_contracts[domain]
            ),
            "fresh_schema": schema_replays[domain],
            "source_snapshot": database_sources_before[domain],
            "post_backup_contract": initial_database_contracts[domain],
        }
        for domain in DATABASE_FILES
    }
    for name, source in managed_sources.items():
        assert_material(
            safe_tree(source),
            managed_before[name],
            label=f"managed source immediately before seal {name}",
        )
    reviewed_gate_receipt_preseal = _reviewed_gate_receipt_contract(
        managed_sources["research_papers"], expected_material=selected_gate_material
    )
    assert_material(
        reviewed_gate_receipt_preseal,
        reviewed_gate_receipt_before,
        label="reviewed total gate receipt immediately before seal",
    )
    reviewed_gate_receipt_target_preseal = _reviewed_gate_receipt_contract(
        paths.output / "research_papers", expected_material=selected_gate_material
    )
    assert_material(
        reviewed_gate_receipt_target_preseal["descriptor"],
        reviewed_gate_receipt_before["descriptor"],
        label="sealed reviewed total gate receipt immediately before seal",
    )
    assert_material(
        _reviewed_chinese_overlay_contract(
            settings.research_papers_database_path,
            overlay_path,
            release_expectation["official_abstract_excerpts"],
            synthetic_test_mode=synthetic_test_mode,
        ),
        chinese_overlay_contract,
        label="formal Chinese overlay immediately before seal",
    )
    seal = {
        "schema_version": SEAL_SCHEMA_VERSION,
        "status": "PASS",
        "synthetic_test_mode": synthetic_test_mode,
        "assembled_at": datetime.now(UTC).isoformat(),
        "delivery_var": str(paths.output),
        "runtime_contract": {
            "code": code_contract,
            "migrations": migration_contract,
            "tools": tools_contract,
            "execution_materials": execution_materials_final,
            "toolchain": {
                "sealed_contract": sealed_toolchain_final,
                "audit": {
                    **toolchain_final,
                    "frozen_pyproject": frozen_pyproject,
                },
            },
            "platform_migration_root": "runtime_contract/migrations/platform",
        },
        "databases": databases,
        "managed_trees": managed_contracts,
        "source_integrity": source_integrity_after,
        "evidence": {
            "candidate_spec": asdict(prepared.candidate_spec),
            "evidence_release_id": prepared.evidence_release_id,
            "repository_snapshot_hash": service_snapshot,
            "counts": evidence_counts,
            "prepared_created": prepared.created,
            "inventory_exports": inventory_contract,
            "prepare_table_delta": changed_tables,
            "prepare_table_allowlist": sorted(PREPARE_MUTABLE_TABLES),
            "reviewed_gate_receipt": reviewed_gate_receipt_contract,
            "chinese_overlay_contract": chinese_overlay_contract,
            "official_abstract_projection_contract": (
                official_abstract_projection_contract
            ),
            "crossref_official_abstract_projection_contract": (
                crossref_official_abstract_projection_contract
            ),
        },
        "paper_lab_papers": paper_lab_papers,
        "resource_contract": resource_contract,
        "research_update_history": {
            "source": source_update_export_contract,
            "sealed_target": final_update_export_contract,
        },
        "source_inputs": {
            "source_delivery_var": str(paths.source_delivery),
            "evidence_candidate_var": str(paths.evidence_candidate),
            "database_snapshots": database_sources_before,
            "database_contracts": database_source_contracts,
            "managed_tree_snapshots": managed_before,
            "execution_materials": execution_materials_final,
            "reviewed_gate_receipt": reviewed_gate_receipt_contract,
        },
    }
    seal_path = paths.output / "ASSEMBLY_SEAL.json"
    seal_sha256 = write_new_json(seal_path, seal)
    try:
        for name, source in managed_sources.items():
            assert_material(
                safe_tree(source),
                managed_before[name],
                label=f"managed source after seal write {name}",
            )
        reviewed_gate_receipt_postseal = _reviewed_gate_receipt_contract(
            managed_sources["research_papers"], expected_material=selected_gate_material
        )
        assert_material(
            reviewed_gate_receipt_postseal,
            reviewed_gate_receipt_before,
            label="reviewed total gate receipt after seal write",
        )
        reviewed_gate_receipt_target_postseal = _reviewed_gate_receipt_contract(
            paths.output / "research_papers", expected_material=selected_gate_material
        )
        assert_material(
            reviewed_gate_receipt_target_postseal["descriptor"],
            reviewed_gate_receipt_before["descriptor"],
            label="sealed reviewed total gate receipt after seal write",
        )
        assert_material(
            _reviewed_chinese_overlay_contract(
                settings.research_papers_database_path,
                overlay_path,
                release_expectation["official_abstract_excerpts"],
                synthetic_test_mode=synthetic_test_mode,
            ),
            chinese_overlay_contract,
            label="formal Chinese overlay after seal write",
        )
    except BaseException:
        seal_path.unlink(missing_ok=True)
        raise
    final_output_manifest = _safe_file_manifest(paths.output)
    matching_seals = sorted(
        relative
        for relative in final_output_manifest
        if PurePosixPath(relative).name.casefold() == "assembly_seal.json"
    )
    if matching_seals != ["ASSEMBLY_SEAL.json"]:
        raise RuntimeSealError("delivery must contain exactly one canonical ASSEMBLY_SEAL.json")
    seal_identity = file_identity(seal_path)
    assert_material(seal_identity["sha256"], seal_sha256, label="assembly seal hash")

    report_payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "PASS",
        "delivery_var": str(paths.output),
        "assembly_seal_path": str(seal_path),
        "assembly_seal_sha256": seal_sha256,
        "assembly_seal_bytes": seal_identity["bytes"],
        "seal_schema_version": SEAL_SCHEMA_VERSION,
        "candidate_spec_sha256": payload_sha256(asdict(prepared.candidate_spec)),
        "evidence_counts": evidence_counts,
        "paper_lab_papers": paper_lab_papers,
    }
    gates_root = (paths.workspace / "project_state" / "gates").resolve(strict=True)
    _ensure_report_parent(paths.report, gates_root)
    report_sha256 = write_new_json(paths.report, report_payload)
    report_payload["report_sha256"] = report_sha256
    return report_payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-delivery-var", type=Path, required=True)
    parser.add_argument("--evidence-candidate-var", type=Path, required=True)
    parser.add_argument("--output-var", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--minimum-evidence-papers", type=int, required=True)
    parser.add_argument("--minimum-evidence-resources", type=int, required=True)
    parser.add_argument("--expected-paper-lab-papers", type=int, default=137)
    args = parser.parse_args()
    result = assemble_delivery(
        source_delivery_var=args.source_delivery_var,
        evidence_candidate_var=args.evidence_candidate_var,
        output_var=args.output_var,
        report=args.report,
        minimum_evidence_papers=args.minimum_evidence_papers,
        minimum_evidence_resources=args.minimum_evidence_resources,
        expected_paper_lab_papers=args.expected_paper_lab_papers,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
