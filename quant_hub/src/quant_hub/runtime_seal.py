"""候选交付的安全枚举、数据库身份与密封校验原语。

这些函数刻意不跟随 symlink/junction/reparse point，也拒绝多硬链接文件。
交付工具、浏览器验收和最终启动使用同一套字节身份算法，避免各自实现产生
“审核的是 A、运行的是 B”的缝隙。
"""

from __future__ import annotations

from contextlib import closing
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import secrets
import sqlite3
import stat
import sys
from typing import Iterable, Sequence

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point


class RuntimeSealError(RuntimeError):
    pass


RUNTIME_DISTRIBUTIONS = (
    "bleach",
    "Flask",
    "Jinja2",
    "latex2mathml",
    "markdown-it-py",
    "MarkupSafe",
    "PyMuPDF",
    "pydantic",
    "typer",
    "Werkzeug",
)


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def payload_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def ensure_within(path: Path, root: Path, *, label: str) -> Path:
    ensure_no_reparse_components(root)
    ensure_no_reparse_components(path)
    resolved = path.resolve(strict=False)
    boundary = root.resolve(strict=True)
    if resolved == boundary or not resolved.is_relative_to(boundary):
        raise RuntimeSealError(f"{label} must be a strict child of {boundary}")
    return resolved


def _stable_payload(path: Path) -> tuple[bytes, os.stat_result]:
    ensure_no_reparse_components(path)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat_is_reparse_point(before)
        or before.st_nlink != 1
    ):
        raise RuntimeSealError(
            f"sealed material must be a regular non-reparse single-link file: {path}"
        )
    payload = path.read_bytes()
    after = path.lstat()
    before_identity = (
        before.st_size,
        before.st_mtime_ns,
        before.st_dev,
        before.st_ino,
        before.st_nlink,
    )
    after_identity = (
        after.st_size,
        after.st_mtime_ns,
        after.st_dev,
        after.st_ino,
        after.st_nlink,
    )
    if (
        before_identity != after_identity
        or len(payload) != after.st_size
        or not stat.S_ISREG(after.st_mode)
        or stat_is_reparse_point(after)
    ):
        raise RuntimeSealError(f"sealed material changed while being read: {path}")
    return payload, after


def _stable_file_digest(path: Path) -> tuple[int, str, os.stat_result]:
    """Hash a stable regular file without materializing it in memory."""

    ensure_no_reparse_components(path)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat_is_reparse_point(before)
        or before.st_nlink != 1
    ):
        raise RuntimeSealError(
            f"sealed material must be a regular non-reparse single-link file: {path}"
        )
    digest = hashlib.sha256()
    total = 0
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    after = path.lstat()
    before_identity = (
        before.st_size,
        before.st_mtime_ns,
        before.st_dev,
        before.st_ino,
        before.st_nlink,
    )
    after_identity = (
        after.st_size,
        after.st_mtime_ns,
        after.st_dev,
        after.st_ino,
        after.st_nlink,
    )
    if (
        before_identity != after_identity
        or total != after.st_size
        or not stat.S_ISREG(after.st_mode)
        or stat_is_reparse_point(after)
    ):
        raise RuntimeSealError(f"sealed material changed while being read: {path}")
    return total, digest.hexdigest(), after


def file_identity(path: Path) -> dict[str, object]:
    size, digest, info = _stable_file_digest(path)
    return {
        "bytes": size,
        "mtime_ns": info.st_mtime_ns,
        "sha256": digest,
    }


def runtime_toolchain() -> dict[str, object]:
    packages: dict[str, str] = {}
    for distribution in RUNTIME_DISTRIBUTIONS:
        try:
            packages[distribution] = metadata.version(distribution)
        except metadata.PackageNotFoundError as error:
            raise RuntimeSealError(
                f"required runtime distribution is missing: {distribution}"
            ) from error
    executable = Path(sys.executable).resolve(strict=True)
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_full_version": sys.version,
        "python_executable": str(executable),
        "python_executable_identity": file_identity(executable),
        "packages": packages,
    }


def _excluded(relative: Path, *, exclude_runtime_caches: bool) -> bool:
    if not exclude_runtime_caches:
        return False
    return any(part == "__pycache__" for part in relative.parts) or relative.suffix in {
        ".pyc",
        ".pyo",
    }


def _safe_tree_records(
    root: Path,
    *,
    exclude_runtime_caches: bool = False,
) -> list[tuple[str, int, str]]:
    ensure_no_reparse_components(root)
    root = root.resolve(strict=True)
    ensure_no_reparse_components(root)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat_is_reparse_point(root_info):
        raise RuntimeSealError(f"sealed tree root is not a real directory: {root}")

    records: list[tuple[str, int, str]] = []
    # 路径碰撞必须在目录组件层拒绝，不能只比较最终文件名。否则在区分
    # 大小写的审核机上，``A/x`` 与 ``a/y`` 可形成两个不同清单，而在
    # Windows 运行机上却折叠到同一目录；空目录也必须参与该判定。
    casefold_paths: dict[str, str] = {}

    def register_path(relative: Path) -> None:
        relative_name = relative.as_posix()
        folded_name = relative_name.casefold()
        previous = casefold_paths.get(folded_name)
        if previous is not None and previous != relative_name:
            raise RuntimeSealError(
                "sealed tree contains a case-fold path collision: "
                f"{previous!r} and {relative_name!r}"
            )
        casefold_paths[folded_name] = relative_name

    def visit(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise RuntimeSealError(f"cannot enumerate sealed tree: {directory}") from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise RuntimeSealError(f"cannot stat sealed material: {path}") from error
            if entry.is_symlink() or stat_is_reparse_point(info):
                raise RuntimeSealError(f"sealed tree contains a link/reparse point: {path}")
            if stat.S_ISDIR(info.st_mode):
                if not _excluded(relative, exclude_runtime_caches=exclude_runtime_caches):
                    register_path(relative)
                    visit(path)
                continue
            if _excluded(relative, exclude_runtime_caches=exclude_runtime_caches):
                continue
            # Windows/Python 3.13 的 DirEntry.stat(follow_symlinks=False)
            # 可能把普通文件 st_nlink 报为 0；真正的 single-link 判定统一由
            # Path.lstat() 驱动的 _stable_payload 完成。
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeSealError(f"sealed tree contains an unsafe file: {path}")
            size, digest, stable_info = _stable_file_digest(path)
            relative_name = relative.as_posix()
            register_path(relative)
            records.append(
                (
                    relative_name,
                    size,
                    digest,
                )
            )

    visit(root)
    return sorted(records)


def safe_tree_file_state(
    root: Path,
    *,
    exclude_runtime_caches: bool = False,
) -> dict[str, dict[str, object]]:
    """返回逐文件字节身份，供“基线文件不可改删、可受控新增”校验使用。"""

    return {
        relative: {"bytes": size, "sha256": file_hash}
        for relative, size, file_hash in _safe_tree_records(
            root,
            exclude_runtime_caches=exclude_runtime_caches,
        )
    }


def safe_tree(
    root: Path,
    *,
    exclude_runtime_caches: bool = False,
) -> dict[str, object]:
    digest = hashlib.sha256()
    total_bytes = 0
    records = _safe_tree_records(
        root,
        exclude_runtime_caches=exclude_runtime_caches,
    )
    for relative, size, file_hash in records:
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


def database_state(path: Path) -> dict[str, object]:
    identity = file_identity(path)
    uri = f"file:{path.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
        try:
            migrations = [
                int(row[0])
                for row in connection.execute(
                    "SELECT version FROM schema_migration ORDER BY version"
                )
            ]
        except sqlite3.OperationalError as error:
            raise RuntimeSealError(f"database has no migration ledger: {path}") from error
        schema_rows = [
            tuple(str(value or "") for value in row)
            for row in connection.execute(
                """
                SELECT type,name,tbl_name,sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type,name,tbl_name
                """
            )
        ]
    if integrity != "ok" or foreign_keys:
        raise RuntimeSealError(f"database integrity failed: {path}")
    return {
        **identity,
        "integrity": integrity,
        "foreign_key_violations": foreign_keys,
        "migration_versions": migrations,
        "schema_sha256": payload_sha256(schema_rows),
    }


def _sql_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _cell(value: object) -> object:
    if isinstance(value, bytes):
        return {"$bytes_hex": value.hex()}
    if value is None or isinstance(value, (str, int, float)):
        return value
    raise RuntimeSealError(f"unsupported SQLite cell type in table seal: {type(value)!r}")


def database_table_state(path: Path) -> dict[str, dict[str, object]]:
    """逐表确定性内容身份；用于跨库发布故障后的白名单恢复校验。"""

    file_identity(path)
    uri = f"file:{path.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    result: dict[str, dict[str, object]] = {}
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        table_names = [
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        ]
        for table_name in table_names:
            columns = [
                str(row[1])
                for row in connection.execute(
                    f"PRAGMA table_info({_sql_identifier(table_name)})"
                )
            ]
            if not columns:
                raise RuntimeSealError(f"table has no visible columns: {table_name}")
            select_columns = ",".join(_sql_identifier(name) for name in columns)
            order_columns = ",".join(_sql_identifier(name) for name in columns)
            digest = hashlib.sha256()
            count = 0
            query = (
                f"SELECT {select_columns} FROM {_sql_identifier(table_name)} "
                f"ORDER BY {order_columns}"
            )
            for row in connection.execute(query):
                digest.update(canonical_json([_cell(value) for value in row]).encode("utf-8"))
                digest.update(b"\n")
                count += 1
            result[table_name] = {
                "rows": count,
                "content_sha256": digest.hexdigest(),
            }
    return result


def database_row_manifest(
    path: Path,
    *,
    include_values_for: Sequence[str] = (),
) -> dict[str, dict[str, object]]:
    """返回稳定的逐行 activation 基线。

    普通表只保存主键和整行 hash；允许在运行期更新少数字段的表才保存原始
    值，避免 bootstrap receipt 无意义地复制整个业务数据库。没有显式主键的
    表以全部列作为自然键；重复自然键会被拒绝，不能形成含糊的恢复基线。
    """

    file_identity(path)
    value_tables = set(include_values_for)
    uri = f"file:{path.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    result: dict[str, dict[str, object]] = {}
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        table_names = [
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        ]
        for table_name in table_names:
            info = list(
                connection.execute(
                    f"PRAGMA table_info({_sql_identifier(table_name)})"
                )
            )
            columns = [str(row[1]) for row in info]
            if not columns:
                raise RuntimeSealError(f"table has no visible columns: {table_name}")
            primary_key = [
                name
                for _ordinal, name in sorted(
                    (
                        (int(row[5]), str(row[1]))
                        for row in info
                        if int(row[5]) > 0
                    ),
                    key=lambda item: item[0],
                )
            ]
            key_kind = "primary_key"
            if not primary_key:
                # SQLite rowid 是物理布局身份，VACUUM/重建后并不稳定。无显式
                # 主键时使用规范化的全部列自然键；完全重复的行没有可审计的
                # 一一对应关系，严格拒绝而不是暗中依赖 rowid。
                primary_key = list(columns)
                key_kind = "natural_key"
            select_columns = ",".join(_sql_identifier(name) for name in columns)
            order_columns = ",".join(_sql_identifier(name) for name in primary_key)
            query = (
                f"SELECT {select_columns} FROM {_sql_identifier(table_name)} "
                f"ORDER BY {order_columns}"
            )
            rows: list[dict[str, object]] = []
            seen_keys: set[str] = set()
            for selected_row in connection.execute(query):
                values = [_cell(value) for value in selected_row]
                by_column = dict(zip(columns, values, strict=True))
                key = [by_column[name] for name in primary_key]
                key_json = canonical_json(key)
                if key_json in seen_keys:
                    raise RuntimeSealError(
                        f"table has no unambiguous stable row key: {table_name}"
                    )
                seen_keys.add(key_json)
                row: dict[str, object] = {
                    "key": key,
                    "row_sha256": payload_sha256(values),
                }
                if table_name in value_tables:
                    row["values"] = values
                rows.append(row)
            result[table_name] = {
                "columns": columns,
                "primary_key": primary_key,
                "key_kind": key_kind,
                "row_count": len(rows),
                "rows": rows,
                "manifest_sha256": payload_sha256(rows),
            }
    return result


def database_contract(path: Path) -> dict[str, object]:
    return {**database_state(path), "tables": database_table_state(path)}


def assert_material(actual: object, expected: object, *, label: str) -> None:
    if actual != expected:
        raise RuntimeSealError(f"sealed material changed: {label}")


def read_json(path: Path, *, schema_version: str | None = None) -> dict[str, object]:
    payload, _ = _stable_payload(path)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeSealError(f"invalid sealed JSON: {path}") from error
    if not isinstance(value, dict):
        raise RuntimeSealError(f"sealed JSON must be an object: {path}")
    if schema_version is not None and value.get("schema_version") != schema_version:
        raise RuntimeSealError(f"unexpected sealed JSON schema: {path}")
    return value


def write_new_json(path: Path, value: object) -> str:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def write_atomic_new_json(path: Path, value: object) -> str:
    """原子且不可覆盖地发布 JSON；中断只会遗留未被消费的临时文件。"""

    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    payload = rendered.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    ensure_no_reparse_components(path)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    reserved = False
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # O_EXCL 先取得最终名字的唯一发布权；replace 只覆盖本次调用创建的空
        # reservation。并发者必定在 O_EXCL 处失败，历史 receipt 永不被覆盖。
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        reserved = True
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        reserved = False
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        if reserved and path.exists():
            # 仅清理由本次调用成功独占、且仍为空的 reservation。进程在这里
            # 崩溃会留下空文件；read_json 会 fail closed，resume 不会接受它。
            try:
                if path.lstat().st_size == 0:
                    path.unlink()
            except OSError:
                pass
        raise
    return hashlib.sha256(payload).hexdigest()


def require_no_sqlite_sidecars(paths: Iterable[Path]) -> None:
    present: list[str] = []
    for path in paths:
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{path}{suffix}")
            if os.path.lexists(sidecar):
                present.append(str(sidecar))
    if present:
        raise RuntimeSealError(
            "sealed databases must be quiescent main-file snapshots: "
            + ", ".join(sorted(present))
        )
