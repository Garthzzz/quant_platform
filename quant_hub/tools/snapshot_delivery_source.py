"""Freeze a read-only running delivery into a quiescent assembly source snapshot.

The source may have zero-byte WAL files and live SHM handles.  This tool never deletes,
checkpoints, migrates, or otherwise writes that source.  It accepts only a stable main-file
state (no non-empty WAL), copies managed trees with no-follow checks, creates each database
through SQLite's backup API, and proves source bytes were unchanged across the operation.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.config import stat_is_reparse_point
from quant_hub.runtime_seal import (
    RuntimeSealError,
    assert_material,
    database_contract,
    file_identity,
    require_no_sqlite_sidecars,
    safe_tree,
    write_new_json,
)


DATABASE_FILES = (
    "platform.sqlite3",
    "archive.sqlite3",
    "research_papers.sqlite3",
    "paper_lab.sqlite3",
)
MANAGED_TREES = (
    "inbox", "objects", "paper_lab", "replay", "research_papers", "exports"
)
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
SEAL_SCHEMA = "qrh-delivery-source-snapshot/v1"
REPORT_SCHEMA = "qrh-delivery-source-snapshot-report/v1"


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _real_directory(path: Path, *, label: str) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise RuntimeSealError(f"{label} must be a real directory: {path}")
    return resolved


def _new_child(path: Path, parent: Path, *, label: str) -> Path:
    parent = _real_directory(parent, label=f"{label} parent")
    target = path.resolve(strict=False)
    if target.parent != parent or _same_path(target, parent):
        raise RuntimeSealError(f"{label} must be a new direct child of {parent}")
    if os.path.lexists(target):
        raise FileExistsError(f"{label} already exists: {target}")
    return target


def _new_report(path: Path, gates_root: Path) -> Path:
    gates = _real_directory(gates_root, label="gates root")
    target = path.resolve(strict=False)
    try:
        target.relative_to(gates)
    except ValueError as error:
        raise RuntimeSealError("snapshot report must stay under project_state/gates") from error
    if target == gates or os.path.lexists(target):
        raise FileExistsError(f"snapshot report must be a new file: {target}")
    return target


def _file_set(database: Path) -> dict[str, dict[str, object] | None]:
    result: dict[str, dict[str, object] | None] = {"main": file_identity(database)}
    for suffix in SIDECAR_SUFFIXES:
        sidecar = Path(f"{database}{suffix}")
        result[suffix] = file_identity(sidecar) if sidecar.is_file() else None
    return result


def _logical_contract(contract: dict[str, object]) -> dict[str, object]:
    return {
        key: contract[key]
        for key in (
            "integrity",
            "foreign_key_violations",
            "migration_versions",
            "schema_sha256",
            "tables",
        )
    }


def _copy_verified_tree(
    source: Path,
    destination: Path,
    expected: dict[str, object],
) -> dict[str, object]:
    assert_material(safe_tree(source), expected, label=f"tree before copy {source}")
    destination.mkdir(exist_ok=False)

    def visit(source_directory: Path, destination_directory: Path) -> None:
        for entry in sorted(os.scandir(source_directory), key=lambda item: item.name):
            source_path = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or stat_is_reparse_point(info):
                raise RuntimeSealError(f"source tree contains link/reparse material: {source_path}")
            target = destination_directory / entry.name
            if stat.S_ISDIR(info.st_mode):
                target.mkdir(exist_ok=False)
                visit(source_path, target)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeSealError(f"source tree contains non-regular material: {source_path}")
            before = file_identity(source_path)
            shutil.copy2(source_path, target)
            assert_material(file_identity(source_path), before, label=f"copied source {source_path}")
            copied = file_identity(target)
            assert_material(
                {key: copied[key] for key in ("bytes", "sha256")},
                {key: before[key] for key in ("bytes", "sha256")},
                label=f"copied target {target}",
            )

    visit(source, destination)
    current_source = safe_tree(source)
    target_tree = safe_tree(destination)
    assert_material(current_source, expected, label=f"tree after copy {source}")
    assert_material(target_tree, expected, label=f"copied tree {destination}")
    return target_tree


def _backup_database(source: Path, target: Path) -> dict[str, object]:
    sidecars = _file_set(source)
    wal = sidecars["-wal"]
    if isinstance(wal, dict) and int(wal["bytes"]) != 0:
        raise RuntimeSealError(
            f"source database has a non-empty WAL and is not snapshot-safe: {source}"
        )
    if sidecars["-journal"] is not None:
        raise RuntimeSealError(f"source database has an active rollback journal: {source}")
    source_contract = database_contract(source)
    uri = f"file:{source.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as source_connection:
        with closing(sqlite3.connect(target)) as target_connection:
            source_connection.backup(target_connection)
            target_connection.commit()
    require_no_sqlite_sidecars((target,))
    target_contract = database_contract(target)
    assert_material(
        _logical_contract(target_contract),
        _logical_contract(source_contract),
        label=f"database logical backup {source.name}",
    )
    assert_material(_file_set(source), sidecars, label=f"database source bytes {source.name}")
    return {
        "source_files": sidecars,
        "source_contract": source_contract,
        "snapshot_contract": target_contract,
    }


def snapshot_delivery_source(
    *,
    source_var: Path,
    output_var: Path,
    report: Path,
    formal_root: Path = FORMAL_ROOT,
    workspace_root: Path = WORKSPACE_ROOT,
) -> dict[str, object]:
    workspace = _real_directory(workspace_root, label="workspace")
    formal = _real_directory(formal_root, label="formal root")
    if formal.parent != workspace:
        raise RuntimeSealError("formal root must be the workspace quant_hub directory")
    var_root = _real_directory(formal / "var", label="var root")
    source = _real_directory(source_var, label="source delivery")
    if source.parent != var_root:
        raise RuntimeSealError("source delivery must be a direct child of quant_hub/var")
    output = _new_child(output_var, var_root, label="output snapshot")
    report_path = _new_report(report, workspace / "project_state" / "gates")

    database_root = _real_directory(source / "db", label="source database root")
    databases = {name: database_root / name for name in DATABASE_FILES}
    for path in databases.values():
        file_identity(path)
    managed = {name: _real_directory(source / name, label=f"managed tree {name}") for name in MANAGED_TREES}

    tree_before = {name: safe_tree(path) for name, path in managed.items()}
    database_files_before = {name: _file_set(path) for name, path in databases.items()}
    output.mkdir(exist_ok=False)
    output_db = output / "db"
    output_db.mkdir(exist_ok=False)

    database_snapshots = {
        name: _backup_database(path, output_db / name)
        for name, path in databases.items()
    }
    tree_snapshots = {
        name: _copy_verified_tree(path, output / name, tree_before[name])
        for name, path in managed.items()
    }

    assert_material(
        {name: _file_set(path) for name, path in databases.items()},
        database_files_before,
        label="source database files final",
    )
    assert_material(
        {name: safe_tree(path) for name, path in managed.items()},
        tree_before,
        label="source managed trees final",
    )
    require_no_sqlite_sidecars(output_db / name for name in DATABASE_FILES)

    seal = {
        "schema_version": SEAL_SCHEMA,
        "status": "PASS",
        "snapshotted_at": datetime.now(UTC).isoformat(),
        "source_var": str(source),
        "output_var": str(output),
        "source_write_performed": False,
        "database_policy": "immutable main-file backup; non-empty WAL and journal fail closed",
        "databases": database_snapshots,
        "managed_trees": tree_snapshots,
        "source_database_files": database_files_before,
        "source_managed_trees": tree_before,
    }
    seal_path = output / "SOURCE_SNAPSHOT_SEAL.json"
    seal_sha256 = write_new_json(seal_path, seal)
    report_payload = {
        "schema_version": REPORT_SCHEMA,
        "status": "PASS",
        "source_var": str(source),
        "output_var": str(output),
        "source_snapshot_seal": str(seal_path),
        "source_snapshot_seal_sha256": seal_sha256,
        "database_count": len(database_snapshots),
        "managed_tree_count": len(tree_snapshots),
        "source_write_performed": False,
    }
    write_new_json(report_path, report_payload)
    return report_payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-var", type=Path, required=True)
    parser.add_argument("--output-var", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    payload = snapshot_delivery_source(
        source_var=args.source_var,
        output_var=args.output_var,
        report=args.report,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
