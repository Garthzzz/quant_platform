"""同一 live Windows writer lease 下的文件型 SQLite canary runner。

本模块只形成 child 自报的 persistent canary evidence。产品入口只接受真实
``LockedWindowsWriterLease``，路径只从其 frozen record 派生；测试入口使用真实
Win32 test-only lease，但不进入 ``__all__``。exact release import/tooling closure 与
controller 现场夹逼属于后续门禁，因此本模块本身不产生 formal qualification。
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import inspect
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sqlite3
import stat
from typing import Any
from urllib.parse import quote

from .local_exact_runtime_canary_evidence import (
    ExactRuntimeCanaryEvidence,
    ExactRuntimeCanaryEvidenceError,
    ExactRuntimeCanaryRequest,
    build_exact_runtime_canary_evidence,
    parse_exact_runtime_canary_evidence_bytes,
    parse_exact_runtime_canary_request_bytes,
)
from .local_release_identity import canonical_bytes, identity_sha256
from .local_windows_writer_lease_holder import (
    LockedWindowsWriterLease,
    WindowsWriterLeaseHolderError,
    _ProductionWindowsApi,
    _TestOnlyLockedWriterLease,
    _read_exact_file,
    _write_through_replace,
)


_PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{48}$")
_DATABASES = (
    ("comments", "comments.sqlite3"),
    ("research_workspace", "research_workspace.sqlite3"),
)
_RUNNER_TOKEN = object()
_TEST_ONLY_TOKEN = object()


class ExactRuntimeCanaryRunnerError(RuntimeError):
    """live lease、固定路径、SQLite 或业务 canary 未闭合。"""


def _checkpoint(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
) -> tuple[dict[str, object], Path, _ProductionWindowsApi]:
    try:
        document, root, api = lease._canary_checkpoint()
    except (WindowsWriterLeaseHolderError, OSError) as error:
        raise ExactRuntimeCanaryRunnerError("writer lease live checkpoint 失败") from error
    if (
        type(document) is not dict
        or not isinstance(root, Path)
        or type(api) is not _ProductionWindowsApi
    ):
        raise ExactRuntimeCanaryRunnerError("writer lease checkpoint provenance 漂移")
    return document, root, api


def _lease_claim(record: dict[str, object]) -> dict[str, object]:
    return {
        "lease_id": record["lease_id"],
        "lease_nonce": record["lease_nonce"],
        "lease_epoch": record["lease_epoch"],
        "lease_record_sha256": record["lease_record_sha256"],
        "authority": "claim_not_independently_observed",
    }


def _assert_request_binding(
    request: ExactRuntimeCanaryRequest, record: dict[str, object]
) -> dict[str, object]:
    document = request.as_dict()
    pairs = {
        "attempt_id": "attempt_id",
        "nonce": "nonce",
        "operation": "operation",
        "role": "role",
        "start_nonce": "start_nonce",
        "authorization_sha256": "authorization_sha256",
        "scm_identity_sha256": "scm_identity_sha256",
        "state_identity_sha256": "state_identity_sha256",
        "release": "release",
    }
    for request_field, record_field in pairs.items():
        if document[request_field] != record.get(record_field):
            raise ExactRuntimeCanaryRunnerError(
                f"canary request.{request_field} 未绑定 live lease record"
            )
    return document


def _safe_component(path: Path, *, directory: bool) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise ExactRuntimeCanaryRunnerError(f"canary 固定路径不可用: {path.name}") from error
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    is_reparse = stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & reparse
    )
    valid_kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if is_reparse or not valid_kind or (not directory and info.st_nlink != 1):
        raise ExactRuntimeCanaryRunnerError(
            f"canary 路径不是普通、非 reparse、单链接对象: {path.name}"
        )
    return info


def _assert_tree_safe(path: Path) -> None:
    _safe_component(path, directory=True)
    for child in path.rglob("*"):
        _safe_component(child, directory=child.is_dir())


def _canary_paths(
    root: Path, request_document: dict[str, object]
) -> dict[str, Path]:
    attempt = str(request_document["attempt_id"])
    nonce = str(request_document["nonce"])
    role = str(request_document["role"])
    workspace = f"{attempt}-{nonce}"
    base = (
        root
        / "tmp"
        / "deployment-attempts"
        / workspace
        / "runtime-canary"
        / role
    )
    expected = (
        PureWindowsPath(str(root))
        / "tmp"
        / "deployment-attempts"
        / workspace
        / "runtime-canary"
        / role
    )
    if PureWindowsPath(str(base)) != expected:
        raise ExactRuntimeCanaryRunnerError("canary 固定路径派生漂移")
    return {
        "base": base,
        "request": base / "request.json",
        "result": base / "result.json",
        "state": base / "state",
        "tmp": base / "tmp",
        "comments": base / "state" / "comments.sqlite3",
        "research_workspace": base / "state" / "research_workspace.sqlite3",
    }


def _assert_layout(paths: dict[str, Path], *, result_allowed: bool) -> None:
    _safe_component(paths["base"], directory=True)
    expected_base = {"request.json", "state", "tmp"}
    if result_allowed:
        expected_base.add("result.json")
    observed_base = {item.name for item in paths["base"].iterdir()}
    if observed_base != expected_base:
        raise ExactRuntimeCanaryRunnerError("runtime-canary 顶层成员不闭合")
    _safe_component(paths["request"], directory=False)
    _safe_component(paths["state"], directory=True)
    _safe_component(paths["tmp"], directory=True)
    if result_allowed:
        _safe_component(paths["result"], directory=False)

    allowed_state: set[str] = set()
    for _name, filename in _DATABASES:
        allowed_state.add(filename)
        _safe_component(paths[_name], directory=False)
    observed_state = {item.name for item in paths["state"].iterdir()}
    if observed_state != allowed_state:
        raise ExactRuntimeCanaryRunnerError(
            "runtime-canary state 终态不是严格 main-only"
        )
    for item in paths["state"].iterdir():
        _safe_component(item, directory=False)

    observed_tmp = {item.name for item in paths["tmp"].iterdir()}
    if not observed_tmp.issubset({"application-runtime"}):
        raise ExactRuntimeCanaryRunnerError("runtime-canary tmp 存在未知成员")
    _assert_tree_safe(paths["tmp"])


def _read_request(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    path: Path,
) -> tuple[ExactRuntimeCanaryRequest, bytes]:
    _record, _root, api = _checkpoint(lease)
    try:
        raw = _read_exact_file(api, path, allow_absent=False)
    except WindowsWriterLeaseHolderError as error:
        raise ExactRuntimeCanaryRunnerError("canary request 读取失败") from error
    if type(raw) is not bytes:
        raise ExactRuntimeCanaryRunnerError("canary request 缺失")
    try:
        request = parse_exact_runtime_canary_request_bytes(raw)
    except ExactRuntimeCanaryEvidenceError as error:
        raise ExactRuntimeCanaryRunnerError("canary request 不合法") from error
    _checkpoint(lease)
    return request, raw


def _sqlite_uri(path: Path, *, mode: str) -> str:
    if mode not in {"ro", "rw"}:
        raise ExactRuntimeCanaryRunnerError("SQLite open mode 无效")
    resolved = path.resolve(strict=True)
    return f"file:{quote(resolved.as_posix(), safe='/:')}?mode={mode}"


def _open_sqlite(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    path: Path,
    *,
    mode: str,
) -> sqlite3.Connection:
    _checkpoint(lease)
    try:
        connection = sqlite3.connect(
            _sqlite_uri(path, mode=mode),
            uri=True,
            timeout=10.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        if mode == "ro":
            connection.execute("PRAGMA query_only=ON")
    except (OSError, sqlite3.Error) as error:
        if "connection" in locals():
            connection.close()
        raise ExactRuntimeCanaryRunnerError("SQLite fixed mode open 失败") from error
    _checkpoint(lease)
    return connection


def _close_sqlite(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    connection: sqlite3.Connection,
) -> None:
    checkpoint_error: BaseException | None = None
    try:
        _checkpoint(lease)
    except BaseException as error:
        checkpoint_error = error
    if connection.in_transaction:
        if checkpoint_error is None:
            checkpoint_error = ExactRuntimeCanaryRunnerError(
                "SQLite close 前仍有活动 transaction"
            )
        try:
            connection.rollback()
        except sqlite3.Error:
            pass
    try:
        connection.close()
    except sqlite3.Error as error:
        raise ExactRuntimeCanaryRunnerError("SQLite close 失败") from error
    try:
        _checkpoint(lease)
    except BaseException as error:
        if checkpoint_error is None:
            checkpoint_error = error
    if checkpoint_error is not None:
        raise checkpoint_error


def _cell(value: object) -> dict[str, object]:
    if value is None:
        return {"type": "null", "value": None}
    if type(value) is int:
        return {"type": "integer", "value": value}
    if type(value) is float and math.isfinite(value):
        return {"type": "real", "value": value.hex()}
    if type(value) is str:
        return {"type": "text", "value": value}
    if type(value) is bytes:
        return {"type": "blob", "value": value.hex()}
    raise ExactRuntimeCanaryRunnerError("SQLite cell 类型不闭合")


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _schema_sha256(connection: sqlite3.Connection) -> str:
    rows = [
        [None if value is None else str(value) for value in row]
        for row in connection.execute(
            """
            SELECT type,name,tbl_name,sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name
            """
        )
    ]
    return identity_sha256(rows)


def _table_digest(connection: sqlite3.Connection, table: str) -> dict[str, object]:
    info = list(connection.execute(f"PRAGMA table_xinfo({_quote_identifier(table)})"))
    columns = [str(row[1]) for row in info if int(row[6]) == 0]
    if not columns:
        raise ExactRuntimeCanaryRunnerError(f"SQLite table 无可见列: {table}")
    primary = [
        name
        for _ordinal, name in sorted(
            ((int(row[5]), str(row[1])) for row in info if int(row[5]) > 0)
        )
    ]
    order = primary or columns
    selected = ",".join(_quote_identifier(column) for column in columns)
    ordered = ",".join(_quote_identifier(column) for column in order)
    digest = hashlib.sha256()
    count = 0
    for row in connection.execute(
        f"SELECT {selected} FROM {_quote_identifier(table)} ORDER BY {ordered}"
    ):
        digest.update(canonical_bytes([_cell(value) for value in row]))
        digest.update(b"\n")
        count += 1
    return {"table": table, "row_count": count, "rows_sha256": digest.hexdigest()}


def _business_summary_sha256(connection: sqlite3.Connection) -> str:
    tables = [
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name
            """
        )
    ]
    return identity_sha256([_table_digest(connection, table) for table in tables])


def _capture_consistent_view(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    path: Path,
) -> dict[str, object]:
    source = _open_sqlite(lease, path, mode="ro")
    try:
        with closing(sqlite3.connect(":memory:", isolation_level=None)) as memory:
            memory.row_factory = sqlite3.Row
            memory.execute("PRAGMA foreign_keys=ON")
            source.backup(memory)
            schema_before = _schema_sha256(memory)
            business_before = _business_summary_sha256(memory)
            memory.execute("VACUUM")
            schema_after = _schema_sha256(memory)
            business_after = _business_summary_sha256(memory)
            if schema_before != schema_after or business_before != business_after:
                raise ExactRuntimeCanaryRunnerError(
                    "consistent view VACUUM 改变 schema/business 语义"
                )
            raw = memory.serialize()
    except sqlite3.Error as error:
        raise ExactRuntimeCanaryRunnerError("SQLite consistent view 失败") from error
    finally:
        _close_sqlite(lease, source)
    if len(raw) < 100 or bytes(raw[:16]) != b"SQLite format 3\x00":
        raise ExactRuntimeCanaryRunnerError("consistent SQLite bytes header 无效")
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema_sha256": schema_after,
        "business_summary_sha256": business_after,
    }


def _execute_write(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    connection: sqlite3.Connection,
    sql: str,
    parameters: tuple[object, ...] = (),
) -> sqlite3.Cursor:
    _checkpoint(lease)
    try:
        cursor = connection.execute(sql, parameters)
    except sqlite3.Error:
        _checkpoint(lease)
        raise
    _checkpoint(lease)
    return cursor


def _run_challenge(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    path: Path,
    *,
    request_sha256: str,
    challenge_nonce: str,
    database_name: str,
) -> dict[str, object]:
    connection = _open_sqlite(lease, path, mode="rw")
    challenge_id = "canary-" + hashlib.sha256(
        f"{request_sha256}:{challenge_nonce}:{database_name}".encode("utf-8")
    ).hexdigest()[:32]
    try:
        if connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name IN "
            "('deployment_canary','deployment_canary_event')"
        ).fetchone()[0] != 0:
            raise ExactRuntimeCanaryRunnerError("deployment challenge 已存在或残留")
        _execute_write(lease, connection, "BEGIN IMMEDIATE")
        try:
            _execute_write(
                lease,
                connection,
                """
                CREATE TABLE deployment_canary(
                    challenge_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL CHECK(revision>=0)
                ) STRICT
                """,
            )
            _execute_write(
                lease,
                connection,
                """
                CREATE TABLE deployment_canary_event(
                    event_id TEXT PRIMARY KEY,
                    challenge_id TEXT NOT NULL REFERENCES deployment_canary(challenge_id),
                    from_revision INTEGER NOT NULL,
                    to_revision INTEGER NOT NULL,
                    event_kind TEXT NOT NULL CHECK(event_kind='cas_applied'),
                    UNIQUE(challenge_id,to_revision)
                ) STRICT
                """,
            )
            _execute_write(
                lease,
                connection,
                """
                CREATE TRIGGER deployment_canary_event_no_update
                BEFORE UPDATE ON deployment_canary_event BEGIN
                  SELECT RAISE(ABORT,'deployment canary events are append-only');
                END
                """,
            )
            _execute_write(
                lease,
                connection,
                """
                CREATE TRIGGER deployment_canary_event_no_delete
                BEFORE DELETE ON deployment_canary_event BEGIN
                  SELECT RAISE(ABORT,'deployment canary events are append-only');
                END
                """,
            )
            inserted = _execute_write(
                lease,
                connection,
                "INSERT INTO deployment_canary(challenge_id,revision) VALUES(?,0)",
                (challenge_id,),
            ).rowcount
            applied = _execute_write(
                lease,
                connection,
                "UPDATE deployment_canary SET revision=1 "
                "WHERE challenge_id=? AND revision=0",
                (challenge_id,),
            ).rowcount
            _execute_write(
                lease,
                connection,
                "INSERT INTO deployment_canary_event VALUES(?,?,0,1,'cas_applied')",
                ("event-" + challenge_id, challenge_id),
            )
            stale = _execute_write(
                lease,
                connection,
                "UPDATE deployment_canary SET revision=2 "
                "WHERE challenge_id=? AND revision=0",
                (challenge_id,),
            ).rowcount
            readback = connection.execute(
                "SELECT revision FROM deployment_canary WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            event_count = connection.execute(
                "SELECT count(*) FROM deployment_canary_event WHERE challenge_id=?",
                (challenge_id,),
            ).fetchone()
            _checkpoint(lease)
            connection.commit()
            _checkpoint(lease)
        except BaseException:
            connection.rollback()
            raise
        numbers = (inserted, applied, stale)
        if any(type(value) is not int for value in numbers):
            raise ExactRuntimeCanaryRunnerError("deployment challenge rowcount 类型漂移")
        if (
            numbers != (1, 1, 0)
            or readback is None
            or type(readback[0]) is not int
            or readback[0] != 1
            or event_count is None
            or type(event_count[0]) is not int
            or event_count[0] != 1
        ):
            raise ExactRuntimeCanaryRunnerError("deployment challenge CAS 结果不闭合")
        outcomes: list[str] = []
        for sql in (
            "UPDATE deployment_canary_event SET event_kind=event_kind "
            "WHERE challenge_id=?",
            "DELETE FROM deployment_canary_event WHERE challenge_id=?",
        ):
            try:
                _execute_write(lease, connection, sql, (challenge_id,))
            except sqlite3.DatabaseError:
                outcomes.append("rejected_by_trigger")
            else:
                raise ExactRuntimeCanaryRunnerError("deployment event 可被改写")
        return {
            "challenge_id": challenge_id,
            "insert_rowcount": inserted,
            "cas_applied_rowcount": applied,
            "stale_cas_rowcount": stale,
            "readback_revision": int(readback[0]),
            "append_only_event_count": int(event_count[0]),
            "event_update_outcome": outcomes[0],
            "event_delete_outcome": outcomes[1],
        }
    finally:
        _close_sqlite(lease, connection)


class _CanaryCommentIdentityAuthority:
    __slots__ = ("_research_id",)

    def __init__(self, research_id: str):
        self._research_id = research_id

    def comment_research_exists(self, research_id: str) -> bool:
        return research_id == self._research_id

    def validate_comment_target(
        self, research_id: str, target: object, material: dict[str, Any]
    ) -> str | None:
        del target
        if research_id != self._research_id or material != {
            "target_kind": "research",
            "document_id": None,
        }:
            return "canary comment target 不闭合"
        return None


def _settings(*, base: Path, release_path: Path, production: bool) -> object:
    from quant_hub.config import Settings

    runtime = base / "tmp" / "application-runtime"
    if production:
        migration_root = (
            release_path / "runtime_contract" / "migrations" / "platform"
        )
    else:
        migration_root = Path(__file__).resolve().parents[3] / "migrations" / "platform"
    return Settings(
        project_root=runtime / "project",
        archive_root=runtime / "archive",
        var_root=runtime / "var",
        database_path=runtime / "var" / "db" / "platform.sqlite3",
        object_root=runtime / "var" / "objects",
        migration_root=migration_root,
    )


def _assert_exact_release_application_loaded(release_path: Path) -> None:
    """Reject installed/tooling application classes masquerading as release code."""

    from quant_hub.archive.contracts import ActorInput
    from quant_hub.collaboration.service import ArchiveCollaboration
    from quant_hub.config import Settings
    from quant_hub.research_workspace.service import ResearchWorkspace

    try:
        release = release_path.resolve(strict=True)
    except OSError as error:
        raise ExactRuntimeCanaryRunnerError("exact release application root 不可用") from error
    _safe_component(release, directory=True)
    for value in (ActorInput, ArchiveCollaboration, Settings, ResearchWorkspace):
        source_name = inspect.getsourcefile(value)
        if type(source_name) is not str:
            raise ExactRuntimeCanaryRunnerError("exact release application source 不可定位")
        try:
            source = Path(source_name).resolve(strict=True)
            source.relative_to(release)
        except (OSError, ValueError) as error:
            raise ExactRuntimeCanaryRunnerError(
                "application class 未从 request exact release 加载"
            ) from error
        _safe_component(source, directory=False)


def _call(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    function: Any,
    *args: object,
    **kwargs: object,
) -> object:
    _checkpoint(lease)
    result = function(*args, **kwargs)
    _checkpoint(lease)
    return result


def _run_archive_business(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    *,
    settings: object,
    path: Path,
    suffix: str,
) -> dict[str, object]:
    from quant_hub.archive.contracts import ActorInput
    from quant_hub.collaboration.service import ArchiveCollaboration

    actor = ActorInput(actor_kind="other", display_name=f"Canary {suffix}")
    research_id = f"canary-research-{suffix}"
    service = ArchiveCollaboration(
        settings,
        comment_database_path=path,
        comment_identity_authority=_CanaryCommentIdentityAuthority(research_id),
    )
    prefix = f"canary-{suffix}"
    created = _call(
        lease,
        service.create_comment,
        research_id,
        actor,
        "canary create",
        idempotency_key=prefix + "-create",
    )
    replay = _call(
        lease,
        service.create_comment,
        research_id,
        actor,
        "canary create",
        idempotency_key=prefix + "-create",
    )
    if not getattr(created, "ok", False) or getattr(created, "status", None) != 201:
        raise ExactRuntimeCanaryRunnerError("Archive canary create 失败")
    if not getattr(replay, "ok", False) or getattr(replay, "replayed", False) is not True:
        raise ExactRuntimeCanaryRunnerError("Archive canary idempotent replay 失败")
    comment_id = str(created.data["comment_id"])
    edited = _call(
        lease,
        service.update_comment,
        comment_id,
        actor,
        "canary edit",
        expected_revision=1,
        idempotency_key=prefix + "-edit",
    )
    stale_edit = _call(
        lease,
        service.update_comment,
        comment_id,
        actor,
        "canary stale edit",
        expected_revision=1,
        idempotency_key=prefix + "-stale-edit",
    )
    deleted = _call(
        lease,
        service.delete_comment,
        comment_id,
        actor,
        expected_revision=2,
        idempotency_key=prefix + "-delete",
    )
    stale_delete = _call(
        lease,
        service.delete_comment,
        comment_id,
        actor,
        expected_revision=2,
        idempotency_key=prefix + "-stale-delete",
    )
    if (
        not edited.ok
        or edited.status != 200
        or stale_edit.ok
        or stale_edit.status != 409
        or stale_edit.error_code != "revision_conflict"
    ):
        raise ExactRuntimeCanaryRunnerError("Archive canary edit/CAS 失败")
    if (
        not deleted.ok
        or deleted.status != 200
        or stale_delete.ok
        or stale_delete.status != 404
        or stale_delete.error_code != "comment_not_found"
    ):
        raise ExactRuntimeCanaryRunnerError("Archive canary delete/CAS 失败")
    return _business_counts(
        lease,
        path,
        database_name="comments",
        comment_id=comment_id,
        prefix=prefix,
    )


def _workspace_node(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease, path: Path
) -> tuple[str, int]:
    connection = _open_sqlite(lease, path, mode="ro")
    try:
        row = connection.execute(
            "SELECT node_id,revision FROM research_workspace_node "
            "ORDER BY node_id LIMIT 1"
        ).fetchone()
    finally:
        _close_sqlite(lease, connection)
    if (
        row is None
        or type(row[0]) is not str
        or not row[0]
        or type(row[1]) is not int
        or row[1] < 1
    ):
        raise ExactRuntimeCanaryRunnerError("Workspace canary 没有固定现存 node")
    return row[0], row[1]


def _run_workspace_business(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    *,
    settings: object,
    path: Path,
    suffix: str,
) -> dict[str, object]:
    from quant_hub.archive.contracts import ActorInput
    from quant_hub.research_workspace.service import ResearchWorkspace

    actor = ActorInput(actor_kind="other", display_name=f"Canary {suffix}")
    node_id, initial_node_revision = _workspace_node(lease, path)
    service = ResearchWorkspace(settings, database_path=path)
    prefix = f"canary-{suffix}"
    created = _call(
        lease,
        service.create_comment,
        node_id,
        actor,
        "canary create",
        idempotency_key=prefix + "-create",
    )
    replay = _call(
        lease,
        service.create_comment,
        node_id,
        actor,
        "canary create",
        idempotency_key=prefix + "-create",
    )
    if not getattr(created, "ok", False) or getattr(created, "status", None) != 201:
        raise ExactRuntimeCanaryRunnerError("Workspace canary create 失败")
    if not getattr(replay, "ok", False) or getattr(replay, "replayed", False) is not True:
        raise ExactRuntimeCanaryRunnerError("Workspace canary idempotent replay 失败")
    comment_id = str(created.data["comment_id"])
    edited = _call(
        lease,
        service.change_comment,
        comment_id,
        actor,
        body="canary edit",
        expected_revision=1,
        idempotency_key=prefix + "-edit",
        delete=False,
    )
    stale_edit = _call(
        lease,
        service.change_comment,
        comment_id,
        actor,
        body="canary stale edit",
        expected_revision=1,
        idempotency_key=prefix + "-stale-edit",
        delete=False,
    )
    deleted = _call(
        lease,
        service.change_comment,
        comment_id,
        actor,
        body=None,
        expected_revision=2,
        idempotency_key=prefix + "-delete",
        delete=True,
    )
    stale_delete = _call(
        lease,
        service.change_comment,
        comment_id,
        actor,
        body=None,
        expected_revision=2,
        idempotency_key=prefix + "-stale-delete",
        delete=True,
    )
    if (
        not edited.ok
        or edited.status != 200
        or stale_edit.ok
        or stale_edit.status != 409
        or stale_edit.error_code != "revision_conflict"
    ):
        raise ExactRuntimeCanaryRunnerError("Workspace canary edit/CAS 失败")
    if (
        not deleted.ok
        or deleted.status != 200
        or stale_delete.ok
        or stale_delete.status != 404
        or stale_delete.error_code != "comment_not_found"
    ):
        raise ExactRuntimeCanaryRunnerError("Workspace canary delete/CAS 失败")
    return _business_counts(
        lease,
        path,
        database_name="research_workspace",
        comment_id=comment_id,
        prefix=prefix,
        node_id=node_id,
        initial_node_revision=initial_node_revision,
    )


def _business_counts(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    path: Path,
    *,
    database_name: str,
    comment_id: str,
    prefix: str,
    node_id: str | None = None,
    initial_node_revision: int | None = None,
) -> dict[str, object]:
    connection = _open_sqlite(lease, path, mode="ro")
    try:
        if database_name == "comments":
            comment_table = "comment"
            event_table = "comment_event"
            receipt_table = "command_receipt"
            family = "archive_comments"
            applied_receipt_predicate = "outcome='applied'"
        else:
            comment_table = "research_workspace_comment"
            event_table = "research_workspace_comment_event"
            receipt_table = "research_workspace_command_receipt"
            family = "workspace_comments"
            applied_receipt_predicate = "http_status BETWEEN 200 AND 299"
        row = connection.execute(
            f"SELECT revision,deleted_at FROM {_quote_identifier(comment_table)} "
            "WHERE comment_id=?",
            (comment_id,),
        ).fetchone()
        event_count = connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(event_table)} WHERE comment_id=?",
            (comment_id,),
        ).fetchone()[0]
        receipt_count = connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(receipt_table)} "
            f"WHERE idempotency_key LIKE ? AND {applied_receipt_predicate}",
            (prefix + "-%",),
        ).fetchone()[0]
        total_receipt_count = connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(receipt_table)} "
            "WHERE idempotency_key LIKE ?",
            (prefix + "-%",),
        ).fetchone()[0]
        deleted_count = connection.execute(
            f"SELECT count(*) FROM {_quote_identifier(comment_table)} "
            "WHERE comment_id=? AND deleted_at IS NOT NULL",
            (comment_id,),
        ).fetchone()[0]
        node_revision = None
        if database_name == "research_workspace":
            if type(node_id) is not str or type(initial_node_revision) is not int:
                raise ExactRuntimeCanaryRunnerError("Workspace node CAS 输入不闭合")
            node_row = connection.execute(
                "SELECT revision FROM research_workspace_node WHERE node_id=?",
                (node_id,),
            ).fetchone()
            node_revision = None if node_row is None else node_row[0]
    finally:
        _close_sqlite(lease, connection)
    if (
        row is None
        or type(row[0]) is not int
        or row[0] != 3
        or row[1] is None
        or type(event_count) is not int
        or type(receipt_count) is not int
        or type(total_receipt_count) is not int
        or type(deleted_count) is not int
        or (event_count, receipt_count, total_receipt_count, deleted_count)
        != (3, 3, 5, 1)
        or (
            database_name == "research_workspace"
            and (
                type(node_revision) is not int
                or type(initial_node_revision) is not int
                or node_revision != initial_node_revision + 3
            )
        )
    ):
        raise ExactRuntimeCanaryRunnerError("business canary 最终计数不闭合")
    return {
        "family": family,
        "create_rowcount": 1,
        "idempotent_replay_rowcount": 0,
        "edit_rowcount": 1,
        "stale_edit_rowcount": 0,
        "soft_delete_rowcount": 1,
        "stale_delete_rowcount": 0,
        "final_revision": 3,
        "event_count": event_count,
        "receipt_count": receipt_count,
        "deleted_row_count": deleted_count,
    }


def _run_business(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    *,
    base: Path,
    release_path: Path,
    production: bool,
    database_name: str,
    path: Path,
    suffix: str,
) -> dict[str, object]:
    from quant_hub.platform.db import (
        _exact_runtime_writer_lease_transaction_scope,
    )

    _checkpoint(lease)
    settings = _settings(
        base=base, release_path=release_path, production=production
    )
    try:
        with _exact_runtime_writer_lease_transaction_scope(
            lease, production=production
        ):
            if database_name == "comments":
                result = _run_archive_business(
                    lease, settings=settings, path=path, suffix=suffix
                )
            else:
                result = _run_workspace_business(
                    lease, settings=settings, path=path, suffix=suffix
                )
    except WindowsWriterLeaseHolderError as error:
        raise ExactRuntimeCanaryRunnerError(
            "application transaction writer lease checkpoint 失败"
        ) from error
    _checkpoint(lease)
    return result


def _members(path: Path) -> list[str]:
    sidecars = tuple(
        suffix
        for suffix in ("-wal", "-shm", "-journal")
        if Path(str(path) + suffix).exists()
    )
    if sidecars:
        raise ExactRuntimeCanaryRunnerError(
            "SQLite final sidecar membership 不是严格 main-only"
        )
    return ["main"]


def _normalize_main_only(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    path: Path,
) -> None:
    """在 application WAL 写入后闭合为 controller 可复验的 main-only 状态。"""

    connection = _open_sqlite(lease, path, mode="rw")
    failure: BaseException | None = None
    try:
        _checkpoint(lease)
        checkpoint = tuple(
            tuple(row)
            for row in connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        )
        _checkpoint(lease)
        journal_mode = tuple(
            tuple(row) for row in connection.execute("PRAGMA journal_mode=DELETE")
        )
        _checkpoint(lease)
        if (
            len(checkpoint) != 1
            or len(checkpoint[0]) != 3
            or any(type(value) is not int for value in checkpoint[0])
            or tuple(int(value) for value in checkpoint[0]) != (0, 0, 0)
            or journal_mode != (("delete",),)
        ):
            raise ExactRuntimeCanaryRunnerError(
                "canary SQLite WAL checkpoint/main-only transition 未闭合"
            )
    except BaseException as error:
        failure = error
    try:
        _close_sqlite(lease, connection)
    except BaseException as close_error:
        raise ExactRuntimeCanaryRunnerError(
            "canary SQLite main-only transition close 失败"
        ) from close_error
    if failure is not None:
        raise failure
    _checkpoint(lease)
    if _members(path) != ["main"]:
        raise ExactRuntimeCanaryRunnerError(
            "canary SQLite main-only transition 留下 sidecar"
        )


def _database_result(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    *,
    paths: dict[str, Path],
    request_document: dict[str, object],
    request_database: dict[str, object],
    challenge_nonce: str,
    production: bool,
) -> dict[str, object]:
    name = str(request_database["database_name"])
    path = paths[name]
    initial = _capture_consistent_view(lease, path)
    if (
        initial["bytes"] != request_database["initial_consistent_bytes"]
        or initial["sha256"] != request_database["initial_consistent_sha256"]
    ):
        raise ExactRuntimeCanaryRunnerError(f"{name} initial consistent view 未绑定 request")
    challenge = _run_challenge(
        lease,
        path,
        request_sha256=str(request_document["request_sha256"]),
        challenge_nonce=challenge_nonce,
        database_name=name,
    )
    suffix = hashlib.sha256(
        f"{request_document['request_sha256']}:{challenge_nonce}:{name}".encode("utf-8")
    ).hexdigest()[:20]
    business = _run_business(
        lease,
        base=paths["base"],
        release_path=Path(str(request_document["release"]["release_path"])),
        production=production,
        database_name=name,
        path=path,
        suffix=suffix,
    )
    _normalize_main_only(lease, path)
    final = _capture_consistent_view(lease, path)
    check = _open_sqlite(lease, path, mode="ro")
    try:
        integrity = [str(row[0]) for row in check.execute("PRAGMA integrity_check")]
        quick = [str(row[0]) for row in check.execute("PRAGMA quick_check")]
        foreign = list(check.execute("PRAGMA foreign_key_check"))
    finally:
        _close_sqlite(lease, check)
    if integrity != ["ok"] or quick != ["ok"]:
        raise ExactRuntimeCanaryRunnerError(f"{name} SQLite integrity/quick check 失败")
    return {
        "database_name": name,
        "request_database_sha256": request_database["request_database_sha256"],
        "initial_consistent_bytes": initial["bytes"],
        "initial_consistent_sha256": initial["sha256"],
        "initial_schema_sha256": initial["schema_sha256"],
        "initial_business_summary_sha256": initial["business_summary_sha256"],
        "challenge": challenge,
        "business_probe": business,
        "final_integrity_check": "ok",
        "final_quick_check": "ok",
        "final_foreign_key_violation_count": len(foreign),
        "final_schema_sha256": final["schema_sha256"],
        "final_business_summary_sha256": final["business_summary_sha256"],
        "final_consistent_bytes": final["bytes"],
        "final_consistent_sha256": final["sha256"],
        "final_members": _members(path),
    }


def _cleanup_application_runtime(base: Path) -> None:
    """只删除本次 runner 创建且已经为空的固定 application runtime 目录。"""

    temporary = base / "tmp"
    runtime = temporary / "application-runtime"
    expected = (
        Path("project/quant_hub/paper_lab/papers"),
        Path("project/quant_hub/paper_lab"),
        Path("project/quant_hub"),
        Path("project/研究修订工作区"),
        Path("project"),
        Path("var/paper_lab/assets"),
        Path("var/paper_lab"),
        Path("var/replay/evidence"),
        Path("var/replay"),
        Path("var/research_papers"),
        Path("var/objects"),
        Path("var/db"),
        Path("var"),
    )
    expected_names = {path.as_posix() for path in expected}
    observed: set[str] = set()
    if not runtime.is_dir():
        raise ExactRuntimeCanaryRunnerError(
            "canary application runtime 固定目录缺失"
        )
    for root, directories, files in os.walk(runtime, topdown=True):
        current = Path(root)
        _safe_component(current, directory=True)
        if files:
            raise ExactRuntimeCanaryRunnerError(
                "canary application runtime 出现未知文件"
            )
        for name in directories:
            target = current / name
            _safe_component(target, directory=True)
            observed.add(target.relative_to(runtime).as_posix())
    if observed != expected_names:
        raise ExactRuntimeCanaryRunnerError(
            "canary application runtime 目录集合漂移"
        )
    try:
        for relative in expected:
            (runtime / relative).rmdir()
        runtime.rmdir()
    except OSError as error:
        raise ExactRuntimeCanaryRunnerError(
            "canary application runtime cleanup 未闭合"
        ) from error
    if tuple(os.scandir(temporary)):
        raise ExactRuntimeCanaryRunnerError("canary tmp controller checkpoint 非空")


def _read_existing_result(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    *,
    path: Path,
    request: ExactRuntimeCanaryRequest,
    challenge_nonce: str,
    lease_claim: dict[str, object],
) -> ExactRuntimeCanaryEvidence:
    _record, _root, api = _checkpoint(lease)
    try:
        raw = _read_exact_file(api, path, allow_absent=False)
        if type(raw) is not bytes:
            raise ExactRuntimeCanaryRunnerError("existing canary result 缺失")
        evidence = parse_exact_runtime_canary_evidence_bytes(raw, request=request)
    except (WindowsWriterLeaseHolderError, ExactRuntimeCanaryEvidenceError) as error:
        raise ExactRuntimeCanaryRunnerError("existing canary result 不合法") from error
    document = evidence.as_dict()
    if (
        document["challenge_nonce"] != challenge_nonce
        or document["writer_lease_claim"] != lease_claim
    ):
        raise ExactRuntimeCanaryRunnerError("existing canary result 不是同 challenge/lease")
    _checkpoint(lease)
    return evidence


def _run(
    lease: LockedWindowsWriterLease | _TestOnlyLockedWriterLease,
    *,
    challenge_nonce: str,
    production: bool,
) -> ExactRuntimeCanaryEvidence:
    if type(challenge_nonce) is not str or _CHALLENGE_RE.fullmatch(challenge_nonce) is None:
        raise ExactRuntimeCanaryRunnerError("canary challenge_nonce 无效")
    record, root, api = _checkpoint(lease)
    if production and PureWindowsPath(str(root)) != _PRODUCTION_ROOT:
        raise ExactRuntimeCanaryRunnerError("production canary root 不是 exact D")

    provisional = {
        "attempt_id": record["attempt_id"],
        "nonce": record["nonce"],
        "role": record["role"],
    }
    paths = _canary_paths(root, provisional)
    result_exists = paths["result"].exists()
    _assert_layout(paths, result_allowed=result_exists)
    request, request_raw = _read_request(lease, paths["request"])
    request_document = _assert_request_binding(request, record)
    if paths != _canary_paths(root, request_document):
        raise ExactRuntimeCanaryRunnerError("request 改变 canary 固定路径")
    claim = _lease_claim(record)
    if production:
        _assert_exact_release_application_loaded(
            Path(str(request_document["release"]["release_path"]))
        )
    if result_exists:
        observed = _read_existing_result(
            lease,
            path=paths["result"],
            request=request,
            challenge_nonce=challenge_nonce,
            lease_claim=claim,
        )
        _assert_layout(paths, result_allowed=True)
        return observed

    database_results = [
        _database_result(
            lease,
            paths=paths,
            request_document=request_document,
            request_database=request_database,
            challenge_nonce=challenge_nonce,
            production=production,
        )
        for request_database in request_document["databases"]
    ]
    _cleanup_application_runtime(paths["base"])
    try:
        evidence_document = build_exact_runtime_canary_evidence(
            {
                "challenge_nonce": challenge_nonce,
                "writer_lease_claim": claim,
                "databases": database_results,
            },
            request=request,
        )
        evidence = ExactRuntimeCanaryEvidence.from_document(
            evidence_document, request=request
        )
    except ExactRuntimeCanaryEvidenceError as error:
        raise ExactRuntimeCanaryRunnerError("canary evidence 构造失败") from error

    request_after, request_raw_after = _read_request(lease, paths["request"])
    if request_raw_after != request_raw or request_after.request_sha256 != request.request_sha256:
        raise ExactRuntimeCanaryRunnerError("canary request 在执行期间漂移")
    _assert_layout(paths, result_allowed=False)
    raw = evidence.canonical_bytes()
    _checkpoint(lease)
    try:
        _write_through_replace(
            api,
            tmp_dir=paths["tmp"],
            final_path=paths["result"],
            raw=raw,
            replace_existing=False,
        )
    except WindowsWriterLeaseHolderError as error:
        raise ExactRuntimeCanaryRunnerError("canary result 原子发布失败") from error
    _checkpoint(lease)
    _assert_layout(paths, result_allowed=True)
    observed = _read_existing_result(
        lease,
        path=paths["result"],
        request=request,
        challenge_nonce=challenge_nonce,
        lease_claim=claim,
    )
    if observed.canonical_bytes() != raw:
        raise ExactRuntimeCanaryRunnerError("canary result readback bytes 漂移")
    _assert_layout(paths, result_allowed=True)
    return observed


class ExactRuntimeCanaryRunner:
    """固定 D 产品 runner；只接受真实 live Windows writer lease。"""

    __slots__ = ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact runtime canary runner 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact runtime canary runner 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, _construction_token: object):
        if _construction_token is not _RUNNER_TOKEN:
            raise TypeError("exact runtime canary runner 必须由 load_exact_d 构造")
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "ExactRuntimeCanaryRunner":
        return cls(_construction_token=_RUNNER_TOKEN)

    def __reduce__(self) -> object:
        raise TypeError("exact runtime canary runner is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def run(
        self, lease: LockedWindowsWriterLease, challenge_nonce: str
    ) -> ExactRuntimeCanaryEvidence:
        if type(lease) is not LockedWindowsWriterLease:
            raise TypeError("production canary runner 只接受 exact live writer lease")
        return _run(lease, challenge_nonce=challenge_nonce, production=True)


class _TestOnlyExactRuntimeCanaryRunnerAdapter:
    __slots__ = ("_token",)

    def __init__(self, *, token: object):
        if token is not _TEST_ONLY_TOKEN:
            raise TypeError("test-only canary runner token 无效")
        self._token = token

    @classmethod
    def for_test_only(cls) -> "_TestOnlyExactRuntimeCanaryRunnerAdapter":
        return cls(token=_TEST_ONLY_TOKEN)

    def run(
        self, lease: _TestOnlyLockedWriterLease, challenge_nonce: str
    ) -> ExactRuntimeCanaryEvidence:
        if type(lease) is not _TestOnlyLockedWriterLease:
            raise TypeError("test-only canary runner lease 类型无效")
        return _run(lease, challenge_nonce=challenge_nonce, production=False)


__all__ = [
    "ExactRuntimeCanaryRunner",
    "ExactRuntimeCanaryRunnerError",
]
