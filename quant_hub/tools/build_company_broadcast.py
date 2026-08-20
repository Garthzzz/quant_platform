#!/usr/bin/env python3
"""Build a relocatable, password-gated Quant Hub company broadcast package."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from typing import Any


WORKSPACE = Path(__file__).resolve().parents[2]
FORMAL_ROOT = WORKSPACE / "quant_hub"
DEFAULT_BASE_PACKAGE = WORKSPACE / "deploy" / "company_broadcast"
DEFAULT_WORKSPACE_SOURCE = WORKSPACE / "研究修订工作区"
DEFAULT_WORKSPACE_DATABASE = FORMAL_ROOT / "data" / "research_workspace.sqlite3"
RUNTIME_TREES = (
    "db",
    "exports",
    "inbox",
    "objects",
    "paper_lab",
    "replay",
    "research_papers",
)
DATABASE_FILES = (
    "archive.sqlite3",
    "paper_lab.sqlite3",
    "platform.sqlite3",
    "research_papers.sqlite3",
)
PROTECTED_ENTRYPOINTS = (
    "tools/viewer/preflight.py",
    "tools/viewer/restart.py",
    "tools/viewer/server.py",
    "tools/viewer/workspace_seed.py",
)
SQLITE_JOURNAL_HEADER_OFFSETS = (
    18,
    19,
    24,
    25,
    26,
    27,
    92,
    93,
    94,
    95,
)
SQLITE_PHYSICAL_NORMALIZATION = "sqlite-journal-header-v1"


class BuildError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_reparse(info: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & flag
    )


def _tree_state(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        raise BuildError(f"missing tree: {root}")
    records: list[tuple[str, int, str]] = []
    folded: dict[str, str] = {}
    for current, directories, filenames in os.walk(root):
        directories[:] = sorted(
            name for name in directories if name != "__pycache__"
        )
        for name in sorted(filenames):
            path = Path(current) / name
            relative = path.relative_to(root)
            if path.suffix in {".pyc", ".pyo"} or "__pycache__" in relative.parts:
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
                raise BuildError(f"unsafe file in package tree: {path}")
            key = relative.as_posix().casefold()
            if key in folded and folded[key] != relative.as_posix():
                raise BuildError(f"case-fold path collision: {relative.as_posix()}")
            folded[key] = relative.as_posix()
            records.append((relative.as_posix(), info.st_size, _sha256(path)))
    digest = hashlib.sha256()
    for relative, size, file_sha256 in sorted(records):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_sha256.encode("ascii"))
        digest.update(b"\n")
    return {
        "files": len(records),
        "bytes": sum(record[1] for record in records),
        "tree_sha256": digest.hexdigest(),
    }


def _copytree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise BuildError(f"missing source directory: {source}")
    shutil.copytree(
        source,
        destination,
        copy_function=shutil.copy2,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def _database_contract(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BuildError(f"missing database: {path}")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or _is_reparse(info) or info.st_nlink != 1:
        raise BuildError(f"database is not an independent regular file: {path}")
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        versions = [
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM schema_migration ORDER BY version"
            )
        ]
        logical_digest = hashlib.sha256()
        logical_lines = 0
        for statement in connection.iterdump():
            logical_digest.update(statement.encode("utf-8"))
            logical_digest.update(b"\n")
            logical_lines += 1
    finally:
        connection.close()
    if integrity is None or integrity[0] != "ok" or violations:
        raise BuildError(f"database integrity failed: {path}")
    payload = path.read_bytes()
    normalized = bytearray(payload)
    for offset in SQLITE_JOURNAL_HEADER_OFFSETS:
        normalized[offset] = 0
    return {
        "migration_versions": versions,
        "bytes": info.st_size,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "physical_normalized_sha256": hashlib.sha256(normalized).hexdigest(),
        "physical_normalization": {
            "schema_version": SQLITE_PHYSICAL_NORMALIZATION,
            "zeroed_offsets": list(SQLITE_JOURNAL_HEADER_OFFSETS),
        },
        "logical_sha256": logical_digest.hexdigest(),
        "logical_lines": logical_lines,
    }


def _backup_database(source: Path, destination: Path) -> None:
    source_connection = sqlite3.connect(
        f"{source.resolve().as_uri()}?mode=ro", uri=True, timeout=30
    )
    destination_connection = sqlite3.connect(destination, timeout=30)
    try:
        source_connection.backup(destination_connection)
        destination_connection.execute("PRAGMA journal_mode=DELETE")
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()


def _workspace_seed_contract(path: Path) -> dict[str, Any]:
    contract = _database_contract(path)
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        present_projects = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM research_workspace_node
                WHERE node_kind='project' AND source_state='present'
                """
            ).fetchone()[0]
        )
        lifecycle_counts = {
            str(status): int(count)
            for status, count in connection.execute(
                """
                SELECT lifecycle_status,COUNT(*)
                FROM research_workspace_node
                WHERE node_kind='project' AND source_state='present'
                GROUP BY lifecycle_status ORDER BY lifecycle_status
                """
            )
        }
        nodes = int(
            connection.execute(
                "SELECT COUNT(*) FROM research_workspace_node"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    if present_projects <= 0:
        raise BuildError("research-workspace seed contains no present projects")
    return {
        "relative_path": "persistent_seed/research_workspace.sqlite3",
        **contract,
        "present_projects": present_projects,
        "nodes": nodes,
        "lifecycle_counts": lifecycle_counts,
    }


def _file_contract(path: Path) -> dict[str, Any]:
    return {"bytes": path.stat().st_size, "sha256": _sha256(path)}


def _write_text(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def build_package(
    *,
    reviewed_runtime: Path,
    output: Path,
    base_package: Path,
    workspace_source: Path,
    workspace_database: Path,
    deployment_id: str,
) -> dict[str, Any]:
    reviewed_runtime = reviewed_runtime.resolve(strict=True)
    base_package = base_package.resolve(strict=True)
    workspace_source = workspace_source.resolve(strict=True)
    workspace_database = workspace_database.resolve(strict=True)
    output = output.resolve(strict=False)
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    if reviewed_runtime.parent != (FORMAL_ROOT / "var").resolve(strict=True):
        raise BuildError("reviewed runtime must be a direct child of quant_hub/var")
    if not (reviewed_runtime / "ASSEMBLY_SEAL.json").is_file():
        raise BuildError("reviewed runtime is missing ASSEMBLY_SEAL.json")

    output.mkdir(parents=True)
    for name in RUNTIME_TREES:
        _copytree(reviewed_runtime / name, output / "runtime" / name)
    _copytree(
        reviewed_runtime / "runtime_contract",
        output / "runtime_contract",
    )
    _copytree(base_package / "tools", output / "tools")
    for name in (
        "requirements.txt",
        "restart_viewer.bat",
        "setup_environment.bat",
    ):
        shutil.copy2(base_package / name, output / name)
    _copytree(
        FORMAL_ROOT / "paper_lab" / "papers",
        output / "quant_hub" / "paper_lab" / "papers",
    )
    _copytree(workspace_source, output / "研究修订工作区")

    archive_placeholder = output / "reference" / "archive"
    archive_placeholder.mkdir(parents=True)
    _write_text(
        archive_placeholder / ".keep",
        "广播包不复制 reference/archive 原始只读正文；页面由已封存数据库与对象资源提供。",
    )

    seed_path = output / "persistent_seed" / "research_workspace.sqlite3"
    seed_path.parent.mkdir(parents=True)
    _backup_database(workspace_database, seed_path)
    seed_contract = _workspace_seed_contract(seed_path)

    full_trees = {
        "runtime_contract/code/src": "full",
        "runtime_contract/migrations": "full",
        "tools/viewer": "full",
        "reference/archive": "full",
        "persistent_seed": "full",
        "研究修订工作区": "full",
        "runtime/exports": "inventory",
        "runtime/inbox": "inventory",
        "runtime/objects": "inventory",
        "runtime/paper_lab": "inventory",
        "runtime/replay": "inventory",
        "runtime/research_papers": "inventory",
        "quant_hub/paper_lab/papers": "inventory",
    }
    trees: dict[str, dict[str, Any]] = {}
    for relative, verification in full_trees.items():
        trees[relative] = {
            **_tree_state(output / relative),
            "startup_verification": verification,
        }

    protected = {
        relative: _file_contract(output / relative)
        for relative in PROTECTED_ENTRYPOINTS
    }
    databases = {
        filename: _database_contract(output / "runtime" / "db" / filename)
        for filename in DATABASE_FILES
    }
    source_seal = _file_contract(reviewed_runtime / "ASSEMBLY_SEAL.json")
    manifest = {
        "schema_version": "qrh-company-broadcast-package/v1",
        "deployment_id": deployment_id,
        "package_revision": "20260731-research-workspace-seed-v1",
        "built_at": _utc_now(),
        "source_delivery": reviewed_runtime.name,
        "source_assembly_seal": source_seal,
        "default_host": "0.0.0.0",
        "default_port": 8765,
        "python_bootstrap": "tools/viewer/bootstrap.py",
        "environment_setup": "setup_environment.bat",
        "default_conda_environment": "quant_hub",
        "access_control": {
            "enabled": True,
            "mode": "form-session-pbkdf2-sha256",
            "password_override": "VIEWER_ACCESS_PASSWORD",
            "unauthenticated_health_path": "/deploymentz",
            "session_cookie": "quant_hub_broadcast_session",
            "protected_entrypoints": protected,
        },
        "persistent_data": {
            "environment_override": "VIEWER_DATA_ROOT",
            "default_policy": "sibling_of_release_directory",
            "default_pattern": "<release_directory_name>_data",
            "comment_database": "comments.sqlite3",
            "research_workspace_database": "research_workspace.sqlite3",
            "research_workspace_seed": seed_contract,
            "seed_policy": (
                "seed when the external workspace database is absent or has zero "
                "domain rows; preserve every non-empty external database"
            ),
            "backup_directory": "backups",
            "inside_release_directory_allowed": False,
        },
        "trees": trees,
        "databases": databases,
    }
    (output / "deployment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    _write_text(
        output / "README_部署说明.md",
        f"""
# Quant Research Hub 公司广播包

部署标识：`{deployment_id}`

## 安装与启动

1. 将 `company_broadcast` 整个目录解压到固定位置。
2. 首次安装运行 `setup_environment.bat`。
3. 运行 `restart_viewer.bat`，等待预检、持久化保护和健康检查全部通过。
4. 浏览器访问 `http://<广播机地址>:8765/`，使用当前广播口令登录。

默认端口为 `8765`。可通过 `VIEWER_PORT` 修改端口，通过
`VIEWER_ACCESS_PASSWORD` 覆盖广播口令。

重启脚本发现旧版 Quant Hub Viewer 占用目标端口时，会同时核验
`/deploymentz`、监听 PID 与进程命令行；三者都能确认为 Quant Hub 后自动
关闭旧交付并接管端口。若端口属于其他程序，仍会拒绝误杀并报错。

## 持久化数据

评论和研究工作区保存在发布目录之外。默认目录与发布根同级，名称为
`<发布目录名>_data`；例如发布根为 `C:\\quant_platform_viewer` 时，默认数据目录为
`C:\\quant_platform_viewer_data`。也可通过 `VIEWER_DATA_ROOT` 指定绝对目录。
升级时应沿用原发布目录名称／位置，或显式把 `VIEWER_DATA_ROOT` 指向旧数据目录。

首次安装且外部 `research_workspace.sqlite3` 不存在或完全为空时，系统会安装
包内种子。本包种子含 {seed_contract['present_projects']} 个研究项目；
任何非空外部工作区数据库都会原样保留，升级不会覆盖研究员内容。

每次重启会先执行完整性、外键与迁移检查，并在外部数据目录的 `backups`
子目录生成可恢复备份。

## 验证

深度预检：

```bat
python -I tools\\viewer\\preflight.py --deep
```

健康检查仅允许广播机本地访问：
`http://127.0.0.1:8765/deploymentz`
""",
    )
    _write_text(
        output / "COPY_MANIFEST.txt",
        f"""
deployment_id={deployment_id}
source_delivery={reviewed_runtime.name}
source_assembly_seal_sha256={source_seal['sha256']}
runtime_databases={len(DATABASE_FILES)}
research_workspace_projects={seed_contract['present_projects']}
research_workspace_nodes={seed_contract['nodes']}
workspace_seed_policy=absent_or_zero_domain_rows_only
access_control=form-session-pbkdf2-sha256
persistent_data_outside_release=true
""",
    )
    return {
        "schema_version": "qrh-company-broadcast-build/v1",
        "status": "PASS",
        "built_at": _utc_now(),
        "output": str(output),
        "deployment_id": deployment_id,
        "source_delivery": reviewed_runtime.name,
        "source_assembly_seal_sha256": source_seal["sha256"],
        "research_workspace_seed": seed_contract,
        "trees": trees,
        "databases": databases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-package", type=Path, default=DEFAULT_BASE_PACKAGE)
    parser.add_argument(
        "--workspace-source", type=Path, default=DEFAULT_WORKSPACE_SOURCE
    )
    parser.add_argument(
        "--workspace-database", type=Path, default=DEFAULT_WORKSPACE_DATABASE
    )
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = build_package(
        reviewed_runtime=args.reviewed_runtime,
        output=args.output,
        base_package=args.base_package,
        workspace_source=args.workspace_source,
        workspace_database=args.workspace_database,
        deployment_id=args.deployment_id,
    )
    report = args.report.resolve(strict=False)
    if report.exists():
        raise FileExistsError(f"report already exists: {report}")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
