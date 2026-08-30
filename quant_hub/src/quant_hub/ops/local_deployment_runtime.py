"""固定 D 根的 B3a SQLite 只读观察与 attempt 隔离探针。

产品构造没有 root、environment、config、hook 或 runtime 注入。测试构造是完全
独立的类型，并且必须显式传入 ``Path``。本切片只形成 controller-side SQLite
诊断证据；exact-release transient 进程、SCM、writer lease 与资格 capability 属于 B3b。
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Mapping
from urllib.parse import quote

from .local_deployment_persistence import (
    CrashReleasedFileLock,
    LocalDeploymentPersistence,
    LockedAttemptWorkspace,
    PRODUCTION_VM_ROOT_TEXT,
)
from .local_release_identity import canonical_bytes, identity_sha256
from .local_runtime_evidence import (
    DEPLOYMENT_CANARY_EVIDENCE_SCHEMA,
    ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA,
    STATE_DATABASE_SEAL_SCHEMA,
    DeploymentCanaryEvidence,
    IsolatedSqliteCopyEvidence,
    LocalRuntimeEvidenceError,
    SqliteCompatibilityManifest,
    StateDatabaseSeal,
    build_deployment_canary_evidence,
    build_isolated_sqlite_copy_evidence,
    build_sqlite_compatibility_manifest,
    build_state_database_seal,
    validate_deployment_canary_evidence,
    validate_isolated_sqlite_copy_evidence,
    validate_state_database_seal,
)


_CONSTRUCTION_TOKEN = object()
_TEST_ONLY_TOKEN = object()
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_DATABASE_FILES = {
    "comments": "comments.sqlite3",
    "research_workspace": "research_workspace.sqlite3",
}
_LOGICAL_VERSIONS = {"comments": 2, "research_workspace": 3}
_OPERATIONS = {"activate_successor", "rollback_to_prior", "bootstrap_first_pair"}
_WORKSPACE_MIGRATION_FILES = (
    (1, "research_workspace", "0001_research_workspace.up.sql", "0001_research_workspace.down.sql"),
    (2, "project_semantics", "0002_project_semantics.up.sql", "0002_project_semantics.down.sql"),
    (
        3,
        "project_creation_command",
        "0003_project_creation_command.up.sql",
        "0003_project_creation_command.down.sql",
    ),
)
_BUSINESS_TABLES = {
    "comments": (
        "actor",
        "command_receipt",
        "comment",
        "comment_event",
        "comment_target",
        "legacy_import_run",
        "outbox_event",
        "progress_command_receipt",
        "progress_topic",
        "progress_topic_event",
    ),
    "research_workspace": (
        "actor",
        "research_workspace_command_receipt",
        "research_workspace_comment",
        "research_workspace_comment_event",
        "research_workspace_event",
        "research_workspace_node",
        "research_workspace_observation",
        "research_workspace_sync_run",
    ),
}


class LocalDeploymentRuntimeError(RuntimeError):
    """固定 runtime 的机械观察无法闭合时抛出。"""


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _validate_component(path: Path, *, directory: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LocalDeploymentRuntimeError("固定 runtime 路径组件不可读") from error
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not expected or _is_reparse(metadata):
        raise LocalDeploymentRuntimeError("固定 runtime 路径含非普通或 reparse 组件")
    if not directory and getattr(metadata, "st_nlink", 1) != 1:
        raise LocalDeploymentRuntimeError("SQLite 文件必须是 single-link 普通文件")
    return metadata


def _validate_directory_chain(path: Path) -> None:
    # 先沿调用者给出的词法路径逐级 lstat，不能先 resolve 后把中间的
    # junction/symlink 悄悄折叠掉。随后再要求最终解析值逐字符不漂移。
    lexical = Path(os.path.abspath(os.fspath(path)))
    if os.name == "nt":
        current = Path(lexical.anchor)
        _validate_component(current, directory=True)
        relative_parts = lexical.parts[1:]
    else:
        current = Path(lexical.anchor or "/")
        _validate_component(current, directory=True)
        relative_parts = lexical.parts[1:]
    for part in relative_parts:
        current /= part
        _validate_component(current, directory=True)
    resolved = lexical.resolve(strict=True)
    if str(resolved) != str(lexical):
        raise LocalDeploymentRuntimeError("固定 runtime 目录链解析后发生漂移")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _sqlite_cell(value: object) -> object:
    if value is None:
        return {"type": "null"}
    if type(value) is int:
        return {"type": "integer", "value": value}
    if type(value) is float:
        if not math.isfinite(value):
            raise LocalDeploymentRuntimeError("SQLite row 含非有限 REAL")
        return {"type": "real", "value_hex": value.hex()}
    if type(value) is str:
        return {"type": "text", "value": value}
    if type(value) is bytes:
        return {"type": "blob", "value_hex": value.hex()}
    raise LocalDeploymentRuntimeError("SQLite row 含不支持的 cell 类型")


@dataclass(frozen=True, slots=True)
class _FileObservation:
    document: dict[str, object]


def _windows_raw_handle_observation(handle_value: int, expected_path: Path) -> tuple[str, str]:
    if os.name != "nt":
        raise LocalDeploymentRuntimeError("Windows handle identity 仅允许 Windows 产品路径")
    import ctypes
    from ctypes import wintypes

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FILETIME),
            ("ftLastAccessTime", FILETIME),
            ("ftLastWriteTime", FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    handle = wintypes.HANDLE(handle_value)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    information = BY_HANDLE_FILE_INFORMATION()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
    get_information.restype = wintypes.BOOL
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    if (
        information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT
        or information.nNumberOfLinks != 1
    ):
        raise LocalDeploymentRuntimeError("Windows SQLite handle 不是 non-reparse single-link")

    get_final = kernel32.GetFinalPathNameByHandleW
    get_final.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final.restype = wintypes.DWORD
    required = get_final(handle, None, 0, 0)
    if required == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = get_final(handle, buffer, len(buffer), 0)
    if written == 0 or written >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    final_path = buffer.value
    if final_path.startswith("\\\\?\\"):
        final_path = final_path[4:]
    if final_path != str(expected_path):
        raise LocalDeploymentRuntimeError("Windows SQLite handle final path 与固定路径不同")

    volume = int(information.dwVolumeSerialNumber)
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    volume_hash = identity_sha256({"scheme": "windows_volume_serial", "value": volume})
    file_hash = identity_sha256(
        {"scheme": "windows_file_id", "volume_serial": volume, "file_index": file_index}
    )
    return volume_hash, file_hash


def _windows_handle_observation(descriptor: int, expected_path: Path) -> tuple[str, str]:
    import msvcrt

    return _windows_raw_handle_observation(msvcrt.get_osfhandle(descriptor), expected_path)


class _WindowsReadOnlyGuardSet:
    """用不共享 write/delete 的真实 handles 围栏只读 seal。

    SQLite 的 WAL reader 可能更新 ``-shm`` read-mark。先持有这些 guards 会让
    ``mode=ro`` 机械降为只读 SHM；未 fence 的现存 writer 也会在 guard acquisition
    阶段被 Windows sharing violation 拒绝，而不是让 sealer 自己改变 SHM 字节。
    """

    __slots__ = ("_paths", "_handles")

    def __init__(self, paths: list[Path]):
        self._paths = paths
        self._handles: list[int] = []

    def __enter__(self) -> "_WindowsReadOnlyGuardSet":
        if os.name != "nt":
            return self
        import ctypes
        from ctypes import wintypes

        generic_read = 0x80000000
        file_share_read = 0x00000001
        open_existing = 3
        open_reparse = 0x00200000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        invalid = ctypes.c_void_p(-1).value
        try:
            for path in self._paths:
                handle = create_file(
                    str(path),
                    generic_read,
                    file_share_read,
                    None,
                    open_existing,
                    open_reparse,
                    None,
                )
                handle_value = int(handle)
                if handle_value == invalid:
                    raise ctypes.WinError(ctypes.get_last_error())
                self._handles.append(handle_value)
                _windows_raw_handle_observation(handle_value, path)
            return self
        except BaseException as error:
            try:
                self.__exit__(None, None, None)
            except BaseException as close_error:
                raise LocalDeploymentRuntimeError(
                    "Windows read-only guard acquisition/cleanup 未闭合"
                ) from close_error
            raise LocalDeploymentRuntimeError(
                "Windows read-only guard 拒绝未 fence writer 或身份漂移"
            ) from error

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if os.name != "nt":
            return
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        close_error: BaseException | None = None
        while self._handles:
            handle = self._handles[-1]
            if close_handle(wintypes.HANDLE(handle)):
                self._handles.pop()
                continue
            close_error = ctypes.WinError(ctypes.get_last_error())
            break
        if close_error is not None:
            raise LocalDeploymentRuntimeError("Windows read-only guard 关闭失败") from close_error


def _standalone_main_bytes(connection: sqlite3.Connection) -> bytes:
    """把 backup 后的一致视图规范为可独立 deserialize 的 main bytes。"""

    raw = connection.serialize()
    if len(raw) < 100 or bytes(raw[:16]) != b"SQLite format 3\x00":
        raise LocalDeploymentRuntimeError("SQLite serialize 没有形成合法 main header")
    if raw[18:20] != b"\x01\x01":
        raise LocalDeploymentRuntimeError("SQLite VACUUM 未正规形成 standalone main header")
    return raw


def _posix_test_handle_observation(descriptor: int, expected_path: Path) -> tuple[str, str]:
    metadata = os.fstat(descriptor)
    proc_link = Path(f"/proc/self/fd/{descriptor}")
    if proc_link.exists():
        observed = Path(os.readlink(proc_link)).resolve(strict=True)
        if observed != expected_path.resolve(strict=True):
            raise LocalDeploymentRuntimeError("POSIX test descriptor final path 不同")
    return (
        identity_sha256({"scheme": "posix_test_device", "value": int(metadata.st_dev)}),
        identity_sha256(
            {
                "scheme": "posix_test_file",
                "device": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
            }
        ),
    )


def _observe_file(path: Path, *, allow_posix_test_only: bool) -> _FileObservation:
    _validate_component(path, directory=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        observed = _validate_component(path, directory=False)
        if (
            not _same_file(before, observed)
            or not stat.S_ISREG(before.st_mode)
            or _is_reparse(before)
            or getattr(before, "st_nlink", 1) != 1
        ):
            raise LocalDeploymentRuntimeError("SQLite open descriptor 与固定路径身份不同")
        if os.name == "nt":
            volume_hash, file_hash = _windows_handle_observation(descriptor, path)
            scheme = "windows_file_id"
        elif allow_posix_test_only:
            volume_hash, file_hash = _posix_test_handle_observation(descriptor, path)
            scheme = "posix_test_only"
        else:
            raise LocalDeploymentRuntimeError("产品 SQLite identity 只允许 Windows")
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after = os.fstat(descriptor)
        confirmed = _validate_component(path, directory=False)
        if (
            not _same_file(before, after)
            or not _same_file(after, confirmed)
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise LocalDeploymentRuntimeError("SQLite 文件在 byte observation 中漂移")
        raw = b"".join(blocks)
        if len(raw) != after.st_size:
            raise LocalDeploymentRuntimeError("SQLite 文件读取长度与 handle 大小不同")
        return _FileObservation(
            {
                "identity_scheme": scheme,
                "bytes": len(raw),
                "mtime_ns": int(after.st_mtime_ns),
                "bytes_sha256": _sha256(raw),
                "volume_identity_sha256": volume_hash,
                "file_identity_sha256": file_hash,
            }
        )
    except OSError as error:
        raise LocalDeploymentRuntimeError("SQLite handle observation 失败") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError as error:
                raise LocalDeploymentRuntimeError("SQLite observation descriptor 关闭失败") from error


def _schema_sha256(connection: sqlite3.Connection) -> str:
    rows = [
        [None if value is None else str(value) for value in row]
        for row in connection.execute(
            """
            SELECT type,name,tbl_name,sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type,name,tbl_name
            """
        )
    ]
    return identity_sha256(rows)


def _table_digest(connection: sqlite3.Connection, table: str) -> dict[str, object]:
    info = list(connection.execute(f"PRAGMA table_xinfo({_quote_identifier(table)})"))
    columns = [str(row[1]) for row in info if int(row[6]) == 0]
    if not columns:
        raise LocalDeploymentRuntimeError(f"业务表缺失或无可见列：{table}")
    primary = [
        name
        for _ordinal, name in sorted(
            ((int(row[5]), str(row[1])) for row in info if int(row[5]) > 0),
            key=lambda item: item[0],
        )
    ]
    if not primary:
        raise LocalDeploymentRuntimeError(f"业务表没有稳定主键：{table}")
    selected = ",".join(_quote_identifier(column) for column in columns)
    ordered = ",".join(_quote_identifier(column) for column in primary)
    digest = hashlib.sha256()
    row_count = 0
    for row in connection.execute(
        f"SELECT {selected} FROM {_quote_identifier(table)} ORDER BY {ordered}"
    ):
        digest.update(canonical_bytes([_sqlite_cell(value) for value in row]))
        digest.update(b"\n")
        row_count += 1
    return {"table": table, "row_count": row_count, "rows_sha256": digest.hexdigest()}


def _count(connection: sqlite3.Connection, sql: str) -> int:
    row = connection.execute(sql).fetchone()
    if row is None or type(row[0]) is not int:
        raise LocalDeploymentRuntimeError("业务计数查询没有返回整数")
    return int(row[0])


def _business_summary(connection: sqlite3.Connection, database: str) -> dict[str, object]:
    if database == "comments":
        queries = {
            "actors": "SELECT count(*) FROM actor",
            "comment_events": "SELECT count(*) FROM comment_event",
            "comment_targets": "SELECT count(*) FROM comment_target",
            "comments_active": "SELECT count(*) FROM comment WHERE deleted_at IS NULL",
            "comments_deleted": "SELECT count(*) FROM comment WHERE deleted_at IS NOT NULL",
            "comments_total": "SELECT count(*) FROM comment",
            "command_receipts": "SELECT count(*) FROM command_receipt",
            "outbox_events": "SELECT count(*) FROM outbox_event",
            "progress_events": "SELECT count(*) FROM progress_topic_event",
            "progress_receipts": "SELECT count(*) FROM progress_command_receipt",
            "progress_topics_active": "SELECT count(*) FROM progress_topic WHERE retired_at IS NULL",
            "progress_topics_total": "SELECT count(*) FROM progress_topic",
        }
    else:
        queries = {
            "actors": "SELECT count(*) FROM actor",
            "command_receipts": "SELECT count(*) FROM research_workspace_command_receipt",
            "comment_events": "SELECT count(*) FROM research_workspace_comment_event",
            "comments_active": "SELECT count(*) FROM research_workspace_comment WHERE deleted_at IS NULL",
            "comments_deleted": "SELECT count(*) FROM research_workspace_comment WHERE deleted_at IS NOT NULL",
            "comments_total": "SELECT count(*) FROM research_workspace_comment",
            "events": "SELECT count(*) FROM research_workspace_event",
            "nodes_missing": "SELECT count(*) FROM research_workspace_node WHERE source_state='missing'",
            "nodes_present": "SELECT count(*) FROM research_workspace_node WHERE source_state='present'",
            "nodes_total": "SELECT count(*) FROM research_workspace_node",
            "observations": "SELECT count(*) FROM research_workspace_observation",
            "sync_runs": "SELECT count(*) FROM research_workspace_sync_run",
        }
    metrics = [
        {"metric": name, "value": _count(connection, sql)}
        for name, sql in sorted(queries.items())
    ]
    table_digests = [
        _table_digest(connection, table) for table in _BUSINESS_TABLES[database]
    ]
    logical_content_sha256 = identity_sha256(table_digests)
    summary_material = {
        "metrics": metrics,
        "table_digests": table_digests,
        "logical_content_sha256": logical_content_sha256,
    }
    return {**summary_material, "summary_sha256": identity_sha256(summary_material)}


@dataclass(frozen=True, slots=True)
class _ConnectionInspection:
    raw_user_version: int
    logical_schema: dict[str, object]
    migration_ledger: list[dict[str, object]]
    sqlite_schema_sha256: str
    integrity_check: str
    quick_check: str
    foreign_key_violation_count: int
    business_summary: dict[str, object]


def _inspect_connection(
    connection: sqlite3.Connection,
    *,
    database: str,
    expected_migration_ledger: list[dict[str, object]],
) -> _ConnectionInspection:
    integrity_rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
    quick_rows = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
    foreign_key_rows = list(connection.execute("PRAGMA foreign_key_check"))
    if integrity_rows != ["ok"] or quick_rows != ["ok"] or foreign_key_rows:
        raise LocalDeploymentRuntimeError("SQLite integrity/quick/FK 检查失败")
    raw_user_version = _count(connection, "PRAGMA user_version")
    if database == "comments":
        store_markers = [
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM comment_store_schema ORDER BY version"
            )
        ]
        target_markers = [
            int(row[0])
            for row in connection.execute(
                "SELECT version FROM comment_target_schema ORDER BY version"
            )
        ]
        if store_markers != [1, 2] or target_markers != [3]:
            raise LocalDeploymentRuntimeError("comments logical marker 不是 v2+[3]")
        logical_schema = {
            "logical_version": 2,
            "comment_store_schema": store_markers,
            "comment_target_schema": target_markers,
        }
        migration_ledger: list[dict[str, object]] = []
    else:
        rows = connection.execute(
            "SELECT version,name,up_sha256,down_sha256 FROM schema_migration ORDER BY version"
        ).fetchall()
        migration_ledger = [
            {
                "version": int(row[0]),
                "name": str(row[1]),
                "up_sha256": str(row[2]),
                "down_sha256": str(row[3]),
            }
            for row in rows
        ]
        if migration_ledger != expected_migration_ledger:
            raise LocalDeploymentRuntimeError("workspace migration ledger 与 exact release 漂移")
        logical_schema = {
            "logical_version": 3,
            "comment_store_schema": [],
            "comment_target_schema": [],
        }
    return _ConnectionInspection(
        raw_user_version=raw_user_version,
        logical_schema=logical_schema,
        migration_ledger=migration_ledger,
        sqlite_schema_sha256=_schema_sha256(connection),
        integrity_check="ok",
        quick_check="ok",
        foreign_key_violation_count=0,
        business_summary=_business_summary(connection, database),
    )


def _open_read_only(path: Path, *, wal_triplet: bool) -> sqlite3.Connection:
    encoded = quote(path.as_posix(), safe="/:")
    query = "mode=ro" if wal_triplet else "mode=ro&immutable=1"
    connection = sqlite3.connect(
        f"file:{encoded}?{query}",
        uri=True,
        timeout=10.0,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
        connection.close()
        raise LocalDeploymentRuntimeError("SQLite query_only 未生效")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@dataclass(frozen=True, slots=True)
class IsolatedCopyResult:
    source_seal: StateDatabaseSeal
    copy_evidence: IsolatedSqliteCopyEvidence


class _RuntimeCore:
    __slots__ = ("_root", "_migration_root", "_test_only", "_allow_posix_test_only")

    def __init__(
        self,
        *,
        root: Path,
        migration_root: Path,
        test_only: bool,
        allow_posix_test_only: bool,
        _construction_token: object,
    ):
        if _construction_token is not _CONSTRUCTION_TOKEN:
            raise LocalDeploymentRuntimeError("runtime 只能由固定工厂构造")
        resolved = root.resolve(strict=True)
        _validate_directory_chain(resolved)
        if not test_only:
            if os.name != "nt" or str(root) != PRODUCTION_VM_ROOT_TEXT or str(resolved) != PRODUCTION_VM_ROOT_TEXT:
                raise LocalDeploymentRuntimeError("产品 runtime 只允许 exact Windows D root")
        self._root = resolved
        self._migration_root = migration_root.resolve(strict=True)
        self._test_only = test_only
        self._allow_posix_test_only = allow_posix_test_only

    def _database_path(self, database: str) -> Path:
        if database not in _DATABASE_FILES:
            raise LocalDeploymentRuntimeError("数据库只允许 comments/research_workspace")
        state = self._root / "state"
        _validate_directory_chain(state)
        path = state / _DATABASE_FILES[database]
        _validate_component(path, directory=False)
        if path.resolve(strict=True).parent != state.resolve(strict=True):
            raise LocalDeploymentRuntimeError("SQLite 不属于 exact state root")
        return path

    def _workspace_migrations(self) -> list[dict[str, object]]:
        _validate_directory_chain(self._migration_root)
        if self._migration_root.name != "research_workspace":
            raise LocalDeploymentRuntimeError("workspace migration root 名称错误")
        entries: list[dict[str, object]] = []
        expected_names = {
            name for _, _, up_name, down_name in _WORKSPACE_MIGRATION_FILES for name in (up_name, down_name)
        }
        observed_names = {entry.name for entry in os.scandir(self._migration_root)}
        if observed_names != expected_names:
            raise LocalDeploymentRuntimeError("workspace migration closure 文件集合漂移")
        for version, name, up_name, down_name in _WORKSPACE_MIGRATION_FILES:
            up = _observe_file(
                self._migration_root / up_name,
                allow_posix_test_only=self._allow_posix_test_only,
            ).document
            down = _observe_file(
                self._migration_root / down_name,
                allow_posix_test_only=self._allow_posix_test_only,
            ).document
            entries.append(
                {
                    "version": version,
                    "name": name,
                    "up_sha256": up["bytes_sha256"],
                    "down_sha256": down["bytes_sha256"],
                }
            )
        return entries

    def _schema_contract(self, database: str) -> tuple[dict[str, object], list[dict[str, object]]]:
        if database == "comments":
            ledger: list[dict[str, object]] = []
            logical = {
                "logical_version": 2,
                "comment_store_schema": [1, 2],
                "comment_target_schema": [3],
            }
        elif database == "research_workspace":
            ledger = self._workspace_migrations()
            logical = {
                "logical_version": 3,
                "comment_store_schema": [],
                "comment_target_schema": [],
            }
        else:
            raise LocalDeploymentRuntimeError("未知 state database")
        return logical, ledger

    def compatibility_manifest(
        self,
        *,
        operation: str,
        database_name: str,
        candidate_release_id: str,
        candidate_release_manifest_sha256: str,
        candidate_read_versions: list[int],
        candidate_write_versions: list[int],
        prior_release_id: str | None,
        prior_release_manifest_sha256: str | None,
        prior_read_versions: list[int] | None,
        prior_write_versions: list[int] | None,
    ) -> SqliteCompatibilityManifest:
        logical, ledger = self._schema_contract(database_name)
        contract_hash = identity_sha256(
            {"logical_schema": logical, "migration_ledger": ledger}
        )
        document = build_sqlite_compatibility_manifest(
            operation=operation,
            database_name=database_name,
            logical_schema_version=_LOGICAL_VERSIONS[database_name],
            candidate_release_id=candidate_release_id,
            candidate_release_manifest_sha256=candidate_release_manifest_sha256,
            candidate_read_versions=candidate_read_versions,
            candidate_write_versions=candidate_write_versions,
            prior_release_id=prior_release_id,
            prior_release_manifest_sha256=prior_release_manifest_sha256,
            prior_read_versions=prior_read_versions,
            prior_write_versions=prior_write_versions,
            schema_contract_sha256=contract_hash,
        )
        return SqliteCompatibilityManifest.from_document(document)

    def _seal_and_optionally_backup(
        self,
        *,
        attempt_id: str,
        nonce: str,
        operation: str,
        database_name: str,
        state_identity_sha256: str,
        compatibility_manifest: SqliteCompatibilityManifest,
        capture_backup: bool,
    ) -> tuple[StateDatabaseSeal, bytes | None, _ConnectionInspection]:
        if operation not in _OPERATIONS:
            raise LocalDeploymentRuntimeError("operation 无效")
        compatibility = compatibility_manifest.as_dict()
        logical, expected_ledger = self._schema_contract(database_name)
        expected_contract = identity_sha256(
            {"logical_schema": logical, "migration_ledger": expected_ledger}
        )
        if (
            compatibility["operation"] != operation
            or compatibility["database_name"] != database_name
            or compatibility["schema_contract_sha256"] != expected_contract
        ):
            raise LocalDeploymentRuntimeError("compatibility aggregate 与本次数据库/operation 不同")

        path = self._database_path(database_name)
        sidecars = {role: Path(str(path) + suffix) for role, suffix in (("main", ""), ("wal", "-wal"), ("shm", "-shm"))}
        journal = Path(str(path) + "-journal")
        try:
            journal.lstat()
        except FileNotFoundError:
            pass
        else:
            raise LocalDeploymentRuntimeError("SQLite rollback journal 不允许参与 seal")
        present = {role: os.path.lexists(member) for role, member in sidecars.items()}
        if not present["main"]:
            raise LocalDeploymentRuntimeError("SQLite main 缺失")
        if present["wal"] != present["shm"]:
            raise LocalDeploymentRuntimeError("SQLite WAL/SHM 必须同时存在或同时缺失")
        wal_triplet = present["wal"]
        before = {
            role: (
                _observe_file(member, allow_posix_test_only=self._allow_posix_test_only)
                if present[role]
                else None
            )
            for role, member in sidecars.items()
        }

        serialized: bytes | None = None
        guarded_paths = [member for role, member in sidecars.items() if present[role]]
        with _WindowsReadOnlyGuardSet(guarded_paths):
            connection = _open_read_only(path, wal_triplet=wal_triplet)
            try:
                inspection = _inspect_connection(
                    connection,
                    database=database_name,
                    expected_migration_ledger=expected_ledger,
                )
                if capture_backup:
                    if not hasattr(sqlite3.Connection, "serialize") or not hasattr(sqlite3.Connection, "deserialize"):
                        raise LocalDeploymentRuntimeError("SQLite runtime 缺 serialize/deserialize")
                    with closing(sqlite3.connect(":memory:", isolation_level=None)) as memory:
                        memory.row_factory = sqlite3.Row
                        memory.execute("PRAGMA foreign_keys=ON")
                        connection.backup(memory)
                        before_vacuum = _inspect_connection(
                            memory,
                            database=database_name,
                            expected_migration_ledger=expected_ledger,
                        )
                        memory.execute("VACUUM")
                        after_vacuum = _inspect_connection(
                            memory,
                            database=database_name,
                            expected_migration_ledger=expected_ledger,
                        )
                        if before_vacuum != after_vacuum or after_vacuum != inspection:
                            raise LocalDeploymentRuntimeError(
                                "isolated memory VACUUM 前后 schema/business 语义漂移"
                            )
                        serialized = _standalone_main_bytes(memory)
            finally:
                connection.close()

            after_present = {
                role: os.path.lexists(member) for role, member in sidecars.items()
            }
            if after_present != present or os.path.lexists(journal):
                raise LocalDeploymentRuntimeError("SQLite read-only seal 创建/删除了 sidecar")
            after = {
                role: (
                    _observe_file(member, allow_posix_test_only=self._allow_posix_test_only)
                    if present[role]
                    else None
                )
                for role, member in sidecars.items()
            }
        if any(
            before[role] is not None
            and after[role] is not None
            and before[role].document != after[role].document
            for role in sidecars
        ):
            raise LocalDeploymentRuntimeError("SQLite main/WAL/SHM 在 seal 前后漂移")

        database_path_text = str(path)
        file_set = []
        for role in ("main", "wal", "shm"):
            observed_before = before[role]
            observed_after = after[role]
            file_set.append(
                {
                    "role": role,
                    "canonical_path": str(sidecars[role]),
                    "presence": "present" if observed_before is not None else "absent",
                    "before": None if observed_before is None else observed_before.document,
                    "after": None if observed_after is None else observed_after.document,
                }
            )
        payload = {
            "schema_version": STATE_DATABASE_SEAL_SCHEMA,
            "attempt_id": attempt_id,
            "nonce": nonce,
            "operation": operation,
            "database_name": database_name,
            "qualification_scope": "diagnostic_only_unresolved_release_closure",
            "runtime_scope": "test_only_explicit_root" if self._test_only else "production_exact_d",
            "canonical_path": database_path_text,
            "state_identity_sha256": state_identity_sha256,
            "open_mode": "wal_triplet_read_only" if wal_triplet else "main_only_immutable",
            "raw_user_version": inspection.raw_user_version,
            "logical_schema": inspection.logical_schema,
            "migration_ledger": inspection.migration_ledger,
            "sqlite_schema_sha256": inspection.sqlite_schema_sha256,
            "integrity_check": inspection.integrity_check,
            "quick_check": inspection.quick_check,
            "foreign_key_violation_count": inspection.foreign_key_violation_count,
            "business_summary": inspection.business_summary,
            "file_set": file_set,
            "compatibility_manifest_sha256": compatibility_manifest.manifest_sha256,
            "result": "read_only_observation",
        }
        if self._test_only:
            document = build_state_database_seal(payload, for_test_only_root=str(self._root))
            seal = StateDatabaseSeal.from_test_document(document, test_root=str(self._root))
        else:
            document = build_state_database_seal(payload)
            seal = StateDatabaseSeal.from_document(document)
        return seal, serialized, inspection

    def seal_database(
        self,
        *,
        attempt_id: str,
        nonce: str,
        operation: str,
        database_name: str,
        state_identity_sha256: str,
        compatibility_manifest: SqliteCompatibilityManifest,
    ) -> StateDatabaseSeal:
        seal, _serialized, _inspection = self._seal_and_optionally_backup(
            attempt_id=attempt_id,
            nonce=nonce,
            operation=operation,
            database_name=database_name,
            state_identity_sha256=state_identity_sha256,
            compatibility_manifest=compatibility_manifest,
            capture_backup=False,
        )
        return seal

    def create_isolated_copy(
        self,
        *,
        workspace: LockedAttemptWorkspace,
        operation: str,
        database_name: str,
        state_identity_sha256: str,
        compatibility_manifest: SqliteCompatibilityManifest,
    ) -> IsolatedCopyResult:
        attempt_id = workspace.attempt_id
        nonce = workspace.nonce
        seal, serialized, source_inspection = self._seal_and_optionally_backup(
            attempt_id=attempt_id,
            nonce=nonce,
            operation=operation,
            database_name=database_name,
            state_identity_sha256=state_identity_sha256,
            compatibility_manifest=compatibility_manifest,
            capture_backup=True,
        )
        if serialized is None or not serialized:
            raise LocalDeploymentRuntimeError("SQLite online backup 没有形成 main bytes")
        workspace.create_exact_directory("state")
        relative = f"state/{_DATABASE_FILES[database_name]}"
        if workspace.preflight(relative, expected_kind="file", allow_absent=True) is None:
            with workspace.open_new_file(relative) as target:
                if target.write_all(serialized) != len(serialized):
                    raise LocalDeploymentRuntimeError("isolated SQLite 写入长度不闭合")
                target.fsync()
        with workspace.pin_sqlite_set(relative) as pinned:
            if pinned.members != ("main",):
                raise LocalDeploymentRuntimeError("isolated SQLite 必须是单一 main")
            destination_raw = pinned.read_bytes("main")
            pinned.assert_unchanged()
        if destination_raw != serialized:
            raise LocalDeploymentRuntimeError("isolated SQLite main bytes 第三值冲突")
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as memory:
            memory.deserialize(destination_raw)
            memory.row_factory = sqlite3.Row
            memory.execute("PRAGMA query_only=ON")
            memory.execute("PRAGMA foreign_keys=ON")
            destination = _inspect_connection(
                memory,
                database=database_name,
                expected_migration_ledger=self._schema_contract(database_name)[1],
            )
        if (
            destination.sqlite_schema_sha256 != source_inspection.sqlite_schema_sha256
            or destination.business_summary != source_inspection.business_summary
        ):
            raise LocalDeploymentRuntimeError("isolated SQLite 与 source 一致视图不同")
        evidence_document = build_isolated_sqlite_copy_evidence(
            {
                "schema_version": ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA,
                "attempt_id": attempt_id,
                "nonce": nonce,
                "operation": operation,
                "database_name": database_name,
                "state_identity_sha256": state_identity_sha256,
                "compatibility_manifest_sha256": compatibility_manifest.manifest_sha256,
                "source_seal_sha256": seal.seal_sha256,
                "sqlite_main_bytes": len(destination_raw),
                "sqlite_main_sha256": _sha256(destination_raw),
                "destination_members": ["main"],
                "destination_integrity_check": destination.integrity_check,
                "destination_quick_check": destination.quick_check,
                "destination_foreign_key_violation_count": destination.foreign_key_violation_count,
                "destination_schema_sha256": destination.sqlite_schema_sha256,
                "destination_business_summary_sha256": destination.business_summary["summary_sha256"],
                "result": "isolated_copy_verified",
            }
        )
        return IsolatedCopyResult(
            source_seal=seal,
            copy_evidence=IsolatedSqliteCopyEvidence.from_document(evidence_document),
        )

    def run_controller_canary(
        self,
        *,
        workspace: LockedAttemptWorkspace,
        database_name: str,
        copy_evidence: IsolatedSqliteCopyEvidence,
    ) -> DeploymentCanaryEvidence:
        copy_document = copy_evidence.as_dict()
        if (
            copy_document["attempt_id"] != workspace.attempt_id
            or copy_document["nonce"] != workspace.nonce
            or copy_document["database_name"] != database_name
        ):
            raise LocalDeploymentRuntimeError("copy evidence 与 workspace attempt/nonce 不同")
        relative = f"state/{_DATABASE_FILES[database_name]}"
        with workspace.pin_sqlite_set(relative) as pinned:
            initial_raw = pinned.read_bytes("main")
            pinned.assert_unchanged()
        if _sha256(initial_raw) != copy_document["sqlite_main_sha256"]:
            raise LocalDeploymentRuntimeError("canary 输入不是已验证 isolated copy")

        expected_ledger = self._schema_contract(database_name)[1]
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as memory:
            memory.deserialize(initial_raw)
            memory.row_factory = sqlite3.Row
            memory.execute("PRAGMA foreign_keys=ON")
            before = _inspect_connection(
                memory,
                database=database_name,
                expected_migration_ledger=expected_ledger,
            )
            challenge = _run_sql_challenge(memory, workspace.attempt_id, workspace.nonce)
            probe = _run_business_probe(
                memory,
                database=database_name,
                attempt_id=workspace.attempt_id,
                nonce=workspace.nonce,
                before_summary_sha256=str(before.business_summary["summary_sha256"]),
            )
            after = _inspect_connection(
                memory,
                database=database_name,
                expected_migration_ledger=expected_ledger,
            )
            probe["after_summary_sha256"] = after.business_summary["summary_sha256"]
            final_raw = memory.serialize()

        workspace.atomic_replace(relative, final_raw)
        with workspace.pin_sqlite_set(relative) as pinned:
            persisted = pinned.read_bytes("main")
            pinned.assert_unchanged()
        if persisted != final_raw:
            raise LocalDeploymentRuntimeError("canary final main 没有 exact 持久化")
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as verifier:
            verifier.deserialize(persisted)
            verifier.row_factory = sqlite3.Row
            verifier.execute("PRAGMA query_only=ON")
            verifier.execute("PRAGMA foreign_keys=ON")
            final = _inspect_connection(
                verifier,
                database=database_name,
                expected_migration_ledger=expected_ledger,
            )
            _verify_sql_challenge(verifier, workspace.attempt_id, workspace.nonce)
        if final.business_summary != after.business_summary:
            raise LocalDeploymentRuntimeError("canary persist 后业务摘要漂移")
        document = build_deployment_canary_evidence(
            {
                "schema_version": DEPLOYMENT_CANARY_EVIDENCE_SCHEMA,
                "attempt_id": workspace.attempt_id,
                "nonce": workspace.nonce,
                "operation": copy_document["operation"],
                "database_name": database_name,
                "state_identity_sha256": copy_document["state_identity_sha256"],
                "compatibility_manifest_sha256": copy_document[
                    "compatibility_manifest_sha256"
                ],
                "execution_lane": "controller_sql_fixture",
                "qualification_scope": "diagnostic_only_not_exact_release",
                "copy_evidence_sha256": copy_evidence.evidence_sha256,
                "challenge": challenge,
                "business_probe": probe,
                "final_main_bytes": len(persisted),
                "final_main_sha256": _sha256(persisted),
                "final_schema_sha256": final.sqlite_schema_sha256,
                "final_business_summary_sha256": final.business_summary["summary_sha256"],
                "result": "controller_fixture_verified",
            }
        )
        return DeploymentCanaryEvidence.from_document(document)

    def commit_evidence(
        self,
        *,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        evidence_id: str,
        evidence: StateDatabaseSeal | IsolatedSqliteCopyEvidence | DeploymentCanaryEvidence,
    ) -> object:
        document = evidence.as_dict()
        if isinstance(evidence, StateDatabaseSeal):
            if self._test_only:
                validated = validate_state_database_seal(
                    document,
                    for_test_only_root=str(self._root),
                )
            else:
                validated = validate_state_database_seal(document)
        elif isinstance(evidence, IsolatedSqliteCopyEvidence):
            validated = validate_isolated_sqlite_copy_evidence(document)
        elif isinstance(evidence, DeploymentCanaryEvidence):
            validated = validate_deployment_canary_evidence(document)
        else:
            raise LocalRuntimeEvidenceError("B2 commit 前必须传已知 B3 closed evidence")
        attempt_id = str(validated["attempt_id"])
        if attempt_id != workspace.attempt_id or validated["nonce"] != workspace.nonce:
            raise LocalRuntimeEvidenceError(
                "B3 evidence 必须绑定同一 B2 lock-bound attempt workspace"
            )
        return persistence.commit_attempt_evidence(
            lock,
            attempt_id,
            evidence_id,
            canonical_bytes(validated),
        )


def _run_sql_challenge(
    connection: sqlite3.Connection,
    attempt_id: str,
    nonce: str,
) -> dict[str, object]:
    challenge_id = "b3_" + hashlib.sha256(f"{attempt_id}:{nonce}".encode()).hexdigest()[:24]
    connection.executescript(
        """
        CREATE TABLE deployment_canary(
            challenge_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL CHECK(revision>=0)
        ) STRICT;
        CREATE TABLE deployment_canary_event(
            event_id TEXT PRIMARY KEY,
            challenge_id TEXT NOT NULL REFERENCES deployment_canary(challenge_id),
            from_revision INTEGER NOT NULL,
            to_revision INTEGER NOT NULL,
            event_kind TEXT NOT NULL CHECK(event_kind='cas_applied'),
            UNIQUE(challenge_id,to_revision)
        ) STRICT;
        CREATE TRIGGER deployment_canary_event_no_update
        BEFORE UPDATE ON deployment_canary_event BEGIN
            SELECT RAISE(ABORT,'deployment canary events are append-only');
        END;
        CREATE TRIGGER deployment_canary_event_no_delete
        BEFORE DELETE ON deployment_canary_event BEGIN
            SELECT RAISE(ABORT,'deployment canary events are append-only');
        END;
        """
    )
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT INTO deployment_canary(challenge_id,revision) VALUES(?,0)",
            (challenge_id,),
        )
        applied = connection.execute(
            "UPDATE deployment_canary SET revision=1 WHERE challenge_id=? AND revision=0",
            (challenge_id,),
        ).rowcount
        if applied != 1:
            raise LocalDeploymentRuntimeError("controller SQL CAS 0→1 不是一行")
        connection.execute(
            "INSERT INTO deployment_canary_event VALUES(?,?,0,1,'cas_applied')",
            (f"evt_{challenge_id}", challenge_id),
        )
        stale = connection.execute(
            "UPDATE deployment_canary SET revision=2 WHERE challenge_id=? AND revision=0",
            (challenge_id,),
        ).rowcount
        readback = int(
            connection.execute(
                "SELECT revision FROM deployment_canary WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()[0]
        )
        events = _count(
            connection,
            "SELECT count(*) FROM deployment_canary_event",
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    if stale != 0 or readback != 1 or events != 1:
        raise LocalDeploymentRuntimeError("stale CAS/readback/append-only event 不闭合")
    outcomes: list[str] = []
    for sql in (
        "UPDATE deployment_canary_event SET event_kind=event_kind",
        "DELETE FROM deployment_canary_event",
    ):
        try:
            connection.execute(sql)
        except sqlite3.DatabaseError:
            outcomes.append("rejected_by_trigger")
        else:
            raise LocalDeploymentRuntimeError("deployment canary event 可被改写")
    return {
        "initial_revision": 0,
        "applied_from_revision": 0,
        "applied_to_revision": 1,
        "applied_rowcount": applied,
        "stale_from_revision": 0,
        "stale_to_revision": 2,
        "stale_rowcount": stale,
        "readback_revision": readback,
        "append_only_event_count": events,
        "event_update_outcome": outcomes[0],
        "event_delete_outcome": outcomes[1],
    }


def _verify_sql_challenge(connection: sqlite3.Connection, attempt_id: str, nonce: str) -> None:
    challenge_id = "b3_" + hashlib.sha256(f"{attempt_id}:{nonce}".encode()).hexdigest()[:24]
    row = connection.execute(
        "SELECT revision FROM deployment_canary WHERE challenge_id=?",
        (challenge_id,),
    ).fetchone()
    event = connection.execute(
        "SELECT from_revision,to_revision,event_kind FROM deployment_canary_event WHERE challenge_id=?",
        (challenge_id,),
    ).fetchone()
    if row is None or int(row[0]) != 1 or event is None or tuple(event) != (0, 1, "cas_applied"):
        raise LocalDeploymentRuntimeError("持久 canary CAS/event 读回不闭合")


def _payload_hash(label: str, suffix: str) -> str:
    return hashlib.sha256(f"{label}:{suffix}".encode()).hexdigest()


def _run_business_probe(
    connection: sqlite3.Connection,
    *,
    database: str,
    attempt_id: str,
    nonce: str,
    before_summary_sha256: str,
) -> dict[str, object]:
    suffix = hashlib.sha256(f"{attempt_id}:{nonce}:{database}".encode()).hexdigest()[:20]
    actor_id = f"act_b3_{suffix}"
    comment_id = f"cmt_b3_{suffix}"
    timestamp = "2000-01-01T00:00:00.000000Z"
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?, 'other', ?, ?)",
            (actor_id, f"B3 Controller {suffix}", timestamp),
        )
        if database == "comments":
            create_rowcount, replay, edit, deleted = _probe_archive_comments(
                connection,
                suffix=suffix,
                actor_id=actor_id,
                comment_id=comment_id,
                timestamp=timestamp,
            )
            event_table = "comment_event"
            receipt_table = "command_receipt"
            comment_table = "comment"
        else:
            create_rowcount, replay, edit, deleted = _probe_workspace_comments(
                connection,
                suffix=suffix,
                actor_id=actor_id,
                comment_id=comment_id,
                timestamp=timestamp,
            )
            event_table = "research_workspace_comment_event"
            receipt_table = "research_workspace_command_receipt"
            comment_table = "research_workspace_comment"
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    row = connection.execute(
        f"SELECT revision,deleted_at FROM {_quote_identifier(comment_table)} WHERE comment_id=?",
        (comment_id,),
    ).fetchone()
    if row is None or int(row[0]) != 3 or row[1] is None:
        raise LocalDeploymentRuntimeError("业务 soft-delete 最终 revision 不闭合")
    event_count = int(
        connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(event_table)} WHERE comment_id=?",
            (comment_id,),
        ).fetchone()[0]
    )
    receipt_count = int(
        connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(receipt_table)} WHERE idempotency_key LIKE ?",
            (f"b3-{suffix}-%",),
        ).fetchone()[0]
    )
    deleted_count = int(
        connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(comment_table)} WHERE comment_id=? AND deleted_at IS NOT NULL",
            (comment_id,),
        ).fetchone()[0]
    )
    return {
        "family": "archive_comments" if database == "comments" else "workspace_comments",
        "create_rowcount": create_rowcount,
        "idempotent_replay_rowcount": replay,
        "edit_rowcount": edit,
        "soft_delete_rowcount": deleted,
        "final_revision": 3,
        "event_count": event_count,
        "receipt_count": receipt_count,
        "deleted_row_count": deleted_count,
        "before_summary_sha256": before_summary_sha256,
        "after_summary_sha256": "0" * 64,
    }


def _archive_receipt(
    connection: sqlite3.Connection,
    *,
    suffix: str,
    index: int,
    command: str,
    actor_id: str,
    aggregate: str,
    timestamp: str,
) -> int:
    result_json = '{"status":"applied"}'
    return connection.execute(
        """
        INSERT OR IGNORE INTO command_receipt(
            receipt_id,idempotency_key,command_name,payload_hash,aggregate_urn,
            actor_id,outcome,result_json,result_hash,http_status,created_at
        ) VALUES(?,?,?,?,?,?,'applied',?,?,200,?)
        """,
        (
            f"rcpt_b3_{suffix}_{index}",
            f"b3-{suffix}-{index}",
            command,
            _payload_hash(command, suffix),
            aggregate,
            actor_id,
            result_json,
            _sha256(result_json.encode()),
            timestamp,
        ),
    ).rowcount


def _probe_archive_comments(
    connection: sqlite3.Connection,
    *,
    suffix: str,
    actor_id: str,
    comment_id: str,
    timestamp: str,
) -> tuple[int, int, int, int]:
    research_id = f"research_b3_{suffix}"
    aggregate = f"qrh:comment:{comment_id}"
    created = connection.execute(
        """
        INSERT INTO comment(comment_id,research_id,actor_id,body,created_at,updated_at,revision,deleted_at)
        VALUES(?,?,?,?,?,?,1,NULL)
        """,
        (comment_id, research_id, actor_id, "B3 create", timestamp, timestamp),
    ).rowcount
    connection.execute(
        "INSERT INTO comment_event VALUES(?,?, 'create',NULL,?,?,1,?)",
        (f"cevt_b3_{suffix}_1", comment_id, _sha256(b"B3 create"), actor_id, timestamp),
    )
    connection.execute(
        """
        INSERT INTO comment_target(
            comment_target_id,comment_id,target_kind,research_id,created_at
        ) VALUES(?,?,'research',?,?)
        """,
        (f"ctgt_b3_{suffix}", comment_id, research_id, timestamp),
    )
    _archive_receipt(
        connection,
        suffix=suffix,
        index=1,
        command="comment.create",
        actor_id=actor_id,
        aggregate=aggregate,
        timestamp=timestamp,
    )
    replay = _archive_receipt(
        connection,
        suffix=suffix,
        index=1,
        command="comment.create",
        actor_id=actor_id,
        aggregate=aggregate,
        timestamp=timestamp,
    )
    edited = connection.execute(
        "UPDATE comment SET body='B3 edit',updated_at=?,revision=2 WHERE comment_id=? AND revision=1",
        (timestamp, comment_id),
    ).rowcount
    connection.execute(
        "INSERT INTO comment_event VALUES(?,?, 'update',?,?,?,2,?)",
        (
            f"cevt_b3_{suffix}_2",
            comment_id,
            _sha256(b"B3 create"),
            _sha256(b"B3 edit"),
            actor_id,
            timestamp,
        ),
    )
    _archive_receipt(
        connection,
        suffix=suffix,
        index=2,
        command="comment.update",
        actor_id=actor_id,
        aggregate=aggregate,
        timestamp=timestamp,
    )
    deleted = connection.execute(
        "UPDATE comment SET deleted_at=?,updated_at=?,revision=3 WHERE comment_id=? AND revision=2",
        (timestamp, timestamp, comment_id),
    ).rowcount
    connection.execute(
        "INSERT INTO comment_event VALUES(?,?, 'delete',?,NULL,?,3,?)",
        (f"cevt_b3_{suffix}_3", comment_id, _sha256(b"B3 edit"), actor_id, timestamp),
    )
    _archive_receipt(
        connection,
        suffix=suffix,
        index=3,
        command="comment.delete",
        actor_id=actor_id,
        aggregate=aggregate,
        timestamp=timestamp,
    )
    return created, replay, edited, deleted


def _workspace_receipt(
    connection: sqlite3.Connection,
    *,
    suffix: str,
    index: int,
    command: str,
    timestamp: str,
) -> int:
    return connection.execute(
        """
        INSERT OR IGNORE INTO research_workspace_command_receipt(
            receipt_id,idempotency_key,command_name,payload_hash,outcome_json,http_status,created_at
        ) VALUES(?,?,?,?,?,200,?)
        """,
        (
            f"wrcpt_b3_{suffix}_{index}",
            f"b3-{suffix}-{index}",
            command,
            _payload_hash(command, suffix),
            '{"status":"applied"}',
            timestamp,
        ),
    ).rowcount


def _probe_workspace_comments(
    connection: sqlite3.Connection,
    *,
    suffix: str,
    actor_id: str,
    comment_id: str,
    timestamp: str,
) -> tuple[int, int, int, int]:
    node_id = f"rnode_b3_{suffix}"
    connection.execute(
        """
        INSERT INTO research_workspace_node(
            node_id,parent_node_id,node_kind,source_entry_kind,source_relative_path,
            source_path_key,source_state,default_title,lifecycle_status,sort_key,
            created_at,updated_at,revision
        ) VALUES(?,NULL,'system','virtual',?,?,'present','B3 Controller Fixture','archived',0,?,?,1)
        """,
        (node_id, f"b3-{suffix}", f"b3-{suffix}", timestamp, timestamp),
    )
    created = connection.execute(
        """
        INSERT INTO research_workspace_comment(
            comment_id,node_id,actor_id,body,created_at,updated_at,revision,deleted_at
        ) VALUES(?,?,?,?,?,?,1,NULL)
        """,
        (comment_id, node_id, actor_id, "B3 create", timestamp, timestamp),
    ).rowcount
    connection.execute(
        "INSERT INTO research_workspace_comment_event VALUES(?,?,'create',NULL,?,?,1,?)",
        (f"wcevt_b3_{suffix}_1", comment_id, _sha256(b"B3 create"), actor_id, timestamp),
    )
    _workspace_receipt(
        connection,
        suffix=suffix,
        index=1,
        command="workspace.comment.create",
        timestamp=timestamp,
    )
    replay = _workspace_receipt(
        connection,
        suffix=suffix,
        index=1,
        command="workspace.comment.create",
        timestamp=timestamp,
    )
    edited = connection.execute(
        """
        UPDATE research_workspace_comment
        SET body='B3 edit',updated_at=?,revision=2
        WHERE comment_id=? AND revision=1
        """,
        (timestamp, comment_id),
    ).rowcount
    connection.execute(
        "INSERT INTO research_workspace_comment_event VALUES(?,?,'update',?,?,?,2,?)",
        (
            f"wcevt_b3_{suffix}_2",
            comment_id,
            _sha256(b"B3 create"),
            _sha256(b"B3 edit"),
            actor_id,
            timestamp,
        ),
    )
    _workspace_receipt(
        connection,
        suffix=suffix,
        index=2,
        command="workspace.comment.update",
        timestamp=timestamp,
    )
    deleted = connection.execute(
        """
        UPDATE research_workspace_comment
        SET deleted_at=?,updated_at=?,revision=3
        WHERE comment_id=? AND revision=2
        """,
        (timestamp, timestamp, comment_id),
    ).rowcount
    connection.execute(
        "INSERT INTO research_workspace_comment_event VALUES(?,?,'delete',?,NULL,?,3,?)",
        (f"wcevt_b3_{suffix}_3", comment_id, _sha256(b"B3 edit"), actor_id, timestamp),
    )
    _workspace_receipt(
        connection,
        suffix=suffix,
        index=3,
        command="workspace.comment.delete",
        timestamp=timestamp,
    )
    return created, replay, edited, deleted


class ProductionWindowsDeploymentRuntime:
    """唯一产品 runtime；工厂没有任何调用者可控参数。"""

    __slots__ = ("_core",)

    def __init__(self, core: _RuntimeCore, *, _construction_token: object):
        if _construction_token is not _CONSTRUCTION_TOKEN:
            raise LocalDeploymentRuntimeError("产品 runtime 必须用 load_exact_d")
        self._core = core

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsDeploymentRuntime":
        project = Path(PRODUCTION_VM_ROOT_TEXT)
        migration_root = project / "quant_hub" / "migrations" / "research_workspace"
        core = _RuntimeCore(
            root=project,
            migration_root=migration_root,
            test_only=False,
            allow_posix_test_only=False,
            _construction_token=_CONSTRUCTION_TOKEN,
        )
        return cls(core, _construction_token=_CONSTRUCTION_TOKEN)

    def compatibility_manifest(self, **kwargs: object) -> SqliteCompatibilityManifest:
        return self._core.compatibility_manifest(**kwargs)  # type: ignore[arg-type]

    def seal_database(self, **kwargs: object) -> StateDatabaseSeal:
        return self._core.seal_database(**kwargs)  # type: ignore[arg-type]

    def create_isolated_copy(self, **kwargs: object) -> IsolatedCopyResult:
        return self._core.create_isolated_copy(**kwargs)  # type: ignore[arg-type]

    def run_controller_canary(self, **kwargs: object) -> DeploymentCanaryEvidence:
        return self._core.run_controller_canary(**kwargs)  # type: ignore[arg-type]

    def commit_evidence(self, **kwargs: object) -> object:
        return self._core.commit_evidence(**kwargs)  # type: ignore[arg-type]


class TestOnlyWindowsDeploymentRuntimeAdapter:
    """与产品类型隔离的显式测试 adapter；CLI/config/env 不得引用。"""

    __slots__ = ("_core", "_test_token")

    def __init__(self, core: _RuntimeCore, *, _test_token: object):
        if _test_token is not _TEST_ONLY_TOKEN:
            raise LocalDeploymentRuntimeError("test-only runtime 必须用 for_test_only")
        self._core = core
        self._test_token = _test_token

    @classmethod
    def for_test_only(
        cls,
        root: Path,
        *,
        migration_root: Path | None = None,
        allow_posix_test_only: bool = False,
    ) -> "TestOnlyWindowsDeploymentRuntimeAdapter":
        if not isinstance(root, Path):
            raise LocalDeploymentRuntimeError("test-only root 必须显式传 Path")
        if os.name != "nt" and not allow_posix_test_only:
            raise LocalDeploymentRuntimeError("POSIX 只允许显式 test-only")
        exact_migrations = migration_root or (
            Path(__file__).resolve().parents[3] / "migrations" / "research_workspace"
        )
        core = _RuntimeCore(
            root=root,
            migration_root=exact_migrations,
            test_only=True,
            allow_posix_test_only=(os.name == "nt" or allow_posix_test_only),
            _construction_token=_CONSTRUCTION_TOKEN,
        )
        return cls(core, _test_token=_TEST_ONLY_TOKEN)

    def compatibility_manifest(self, **kwargs: object) -> SqliteCompatibilityManifest:
        return self._core.compatibility_manifest(**kwargs)  # type: ignore[arg-type]

    def seal_database(self, **kwargs: object) -> StateDatabaseSeal:
        return self._core.seal_database(**kwargs)  # type: ignore[arg-type]

    def create_isolated_copy(self, **kwargs: object) -> IsolatedCopyResult:
        return self._core.create_isolated_copy(**kwargs)  # type: ignore[arg-type]

    def run_controller_canary(self, **kwargs: object) -> DeploymentCanaryEvidence:
        return self._core.run_controller_canary(**kwargs)  # type: ignore[arg-type]

    def commit_evidence(self, **kwargs: object) -> object:
        return self._core.commit_evidence(**kwargs)  # type: ignore[arg-type]


__all__ = [
    "IsolatedCopyResult",
    "LocalDeploymentRuntimeError",
    "ProductionWindowsDeploymentRuntime",
    "TestOnlyWindowsDeploymentRuntimeAdapter",
]
