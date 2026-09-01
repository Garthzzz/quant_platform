"""e.4.2 controller 对 canary HTTP 结果与最终 SQLite 状态的现场复验。

产品入口只接受同一条 exact live SCM/endpoint/writer capability 链以及
``LockedExactRuntimeCanaryInput``，且唯一网络动作是固定 localhost 端点的 fresh POST。
数据库路径只能从受锁输入的固定布局派生；模块私有路径参数仅供 SQLite 复验测试。
本切片形成的是 ``live_observed_not_formally_qualified`` 现场能力，不能代替后续正式
qualification gate。
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from pathlib import PurePosixPath
import secrets
import sqlite3
from typing import Mapping

from .local_exact_runtime_canary_evidence import (
    ExactRuntimeCanaryEvidence,
    ExactRuntimeCanaryEvidenceError,
    ExactRuntimeCanaryRequest,
    parse_exact_runtime_canary_evidence_bytes,
)
from .local_exact_runtime_canary_input import LockedExactRuntimeCanaryInput
from .local_exact_runtime_canary_observer import (
    ExactRuntimeCanaryHttpResponse,
    ExactRuntimeCanaryTransportError,
    ProductionExactRuntimeCanaryTransport,
)
from .local_exact_runtime_controller_tooling_observer import (
    ExactRuntimeControllerToolingObservationEvidence,
    ExactRuntimeControllerToolingObserverError,
    LockedExactRuntimeControllerToolingObservation,
    ProductionExactRuntimeControllerToolingObserver,
)
from .local_release_identity import canonical_bytes
from .local_windows_endpoint_evidence import WindowsEndpointObservationEvidence
from .local_windows_endpoint_observer import LockedWindowsEndpointObservation
from .local_windows_scm_process_evidence import (
    WindowsScmProcessObservationEvidence,
)
from .local_windows_scm_process_observer import (
    LockedWindowsScmProcessObservation,
)
from .local_windows_writer_lease_evidence import (
    WindowsWriterLeaseObservationEvidence,
)
from .local_windows_writer_lease_observer import (
    LockedWindowsWriterLeaseObservation,
)


_DATABASE_ORDER = ("comments", "research_workspace")
_DATABASE_FILES = {
    "comments": "comments.sqlite3",
    "research_workspace": "research_workspace.sqlite3",
}
_LIVE_OBSERVER_TOKEN = object()
_LIVE_OBSERVATION_TOKEN = object()
_LIVE_OBSERVATION_SCHEMA = "qrh-exact-runtime-canary-live-observation/v1"
_LIVE_OBSERVATION_SCOPE = "exact_runtime_canary_live_observed_not_qualified"


class ExactRuntimeCanaryLiveObserverError(RuntimeError):
    """controller 不能把 result 与两个真实最终 SQLite 闭合。"""


@dataclass(frozen=True, slots=True)
class _DatabaseVerification:
    database_name: str
    final_consistent_bytes: int
    final_consistent_sha256: str
    final_schema_sha256: str
    final_business_summary_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "database_name": self.database_name,
            "final_consistent_bytes": self.final_consistent_bytes,
            "final_consistent_sha256": self.final_consistent_sha256,
            "final_schema_sha256": self.final_schema_sha256,
            "final_business_summary_sha256": self.final_business_summary_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExactRuntimeCanaryLiveObservationEvidence:
    """可持久化聚合摘要；它本身不恢复任何 live capability。"""

    _raw: bytes

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation evidence 内部 bytes 损坏"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


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
    raise ExactRuntimeCanaryLiveObserverError("SQLite cell 类型不闭合")


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
    return hashlib.sha256(canonical_bytes(rows)).hexdigest()


def _table_digest(
    connection: sqlite3.Connection, table: str
) -> dict[str, object]:
    info = list(
        connection.execute(f"PRAGMA table_xinfo({_quote_identifier(table)})")
    )
    columns = [str(row[1]) for row in info if int(row[6]) == 0]
    if not columns:
        raise ExactRuntimeCanaryLiveObserverError(
            f"SQLite table 无可见列: {table}"
        )
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
    return {
        "table": table,
        "row_count": count,
        "rows_sha256": digest.hexdigest(),
    }


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
    documents = [_table_digest(connection, table) for table in tables]
    return hashlib.sha256(canonical_bytes(documents)).hexdigest()


def _exact_rows(
    connection: sqlite3.Connection,
    sql: str,
    parameters: tuple[object, ...] = (),
) -> tuple[tuple[object, ...], ...]:
    try:
        return tuple(
            tuple(row) for row in connection.execute(sql, parameters).fetchall()
        )
    except sqlite3.Error as error:
        raise ExactRuntimeCanaryLiveObserverError(
            "controller business verification SQL 失败"
        ) from error


def _verify_challenge(
    connection: sqlite3.Connection,
    *,
    challenge_id: str,
) -> None:
    if _exact_rows(
        connection,
        "SELECT challenge_id,revision FROM deployment_canary",
    ) != ((challenge_id, 1),):
        raise ExactRuntimeCanaryLiveObserverError(
            "deployment canary CAS row 未真实持久化"
        )
    if _exact_rows(
        connection,
        "SELECT event_id,challenge_id,from_revision,to_revision,event_kind "
        "FROM deployment_canary_event",
    ) != (("event-" + challenge_id, challenge_id, 0, 1, "cas_applied"),):
        raise ExactRuntimeCanaryLiveObserverError(
            "deployment canary append-only event 未真实持久化"
        )


def _verify_archive_business(
    connection: sqlite3.Connection,
    *,
    suffix: str,
) -> None:
    research_id = f"canary-research-{suffix}"
    prefix = f"canary-{suffix}"
    rows = _exact_rows(
        connection,
        """
        SELECT comment.comment_id,comment.revision,comment.deleted_at,
               comment.body,actor.display_name
        FROM comment JOIN actor ON actor.actor_id=comment.actor_id
        WHERE comment.research_id=?
        """,
        (research_id,),
    )
    if (
        len(rows) != 1
        or type(rows[0][0]) is not str
        or rows[0][1] != 3
        or type(rows[0][2]) is not str
        or rows[0][3] != "canary edit"
        or rows[0][4] != f"Canary {suffix}"
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "Archive comment canary 实体未闭合"
        )
    comment_id = str(rows[0][0])
    if _exact_rows(
        connection,
        "SELECT event_type,revision FROM comment_event "
        "WHERE comment_id=? ORDER BY revision",
        (comment_id,),
    ) != (("create", 1), ("update", 2), ("delete", 3)):
        raise ExactRuntimeCanaryLiveObserverError(
            "Archive comment event 序列未闭合"
        )
    receipts = _exact_rows(
        connection,
        "SELECT idempotency_key,outcome,http_status FROM command_receipt "
        "WHERE idempotency_key LIKE ? ORDER BY idempotency_key",
        (prefix + "-%",),
    )
    expected_keys = {
        prefix + "-create",
        prefix + "-edit",
        prefix + "-stale-edit",
        prefix + "-delete",
        prefix + "-stale-delete",
    }
    if (
        len(receipts) != 5
        or {str(row[0]) for row in receipts} != expected_keys
        or sum(row[1] == "applied" for row in receipts) != 3
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "Archive command receipt 集合未闭合"
        )


def _verify_workspace_business(
    connection: sqlite3.Connection,
    *,
    suffix: str,
    initial_node: tuple[str, int],
) -> None:
    prefix = f"canary-{suffix}"
    node_id, initial_revision = initial_node
    rows = _exact_rows(
        connection,
        """
        SELECT comment.comment_id,comment.node_id,comment.revision,
               comment.deleted_at,comment.body,actor.display_name
        FROM research_workspace_comment AS comment
        JOIN actor ON actor.actor_id=comment.actor_id
        WHERE actor.display_name=?
        """,
        (f"Canary {suffix}",),
    )
    if (
        len(rows) != 1
        or type(rows[0][0]) is not str
        or rows[0][1] != node_id
        or rows[0][2] != 3
        or type(rows[0][3]) is not str
        or rows[0][4] != "canary edit"
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "Workspace comment canary 实体未闭合"
        )
    comment_id = str(rows[0][0])
    if _exact_rows(
        connection,
        "SELECT event_type,revision FROM research_workspace_comment_event "
        "WHERE comment_id=? ORDER BY revision",
        (comment_id,),
    ) != (("create", 1), ("update", 2), ("delete", 3)):
        raise ExactRuntimeCanaryLiveObserverError(
            "Workspace comment event 序列未闭合"
        )
    receipts = _exact_rows(
        connection,
        "SELECT idempotency_key,http_status FROM research_workspace_command_receipt "
        "WHERE idempotency_key LIKE ? ORDER BY idempotency_key",
        (prefix + "-%",),
    )
    expected_keys = {
        prefix + "-create",
        prefix + "-edit",
        prefix + "-stale-edit",
        prefix + "-delete",
        prefix + "-stale-delete",
    }
    if (
        len(receipts) != 5
        or {str(row[0]) for row in receipts} != expected_keys
        or sum(200 <= int(row[1]) <= 299 for row in receipts) != 3
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "Workspace command receipt 集合未闭合"
        )
    if _exact_rows(
        connection,
        "SELECT revision FROM research_workspace_node WHERE node_id=?",
        (node_id,),
    ) != ((initial_revision + 3,),):
        raise ExactRuntimeCanaryLiveObserverError(
            "Workspace node CAS revision 未闭合"
        )


def _consistent_snapshot(path: Path) -> tuple[sqlite3.Connection, dict[str, object]]:
    uri = f"file:{path.as_posix()}?mode=ro"
    source: sqlite3.Connection | None = None
    memory: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(uri, uri=True, isolation_level=None)
        source.execute("PRAGMA query_only=ON")
        memory = sqlite3.connect(":memory:", isolation_level=None)
        memory.execute("PRAGMA foreign_keys=ON")
        source.backup(memory)
        source.close()
        source = None
        schema_before = _schema_sha256(memory)
        business_before = _business_summary_sha256(memory)
        memory.execute("VACUUM")
        schema_after = _schema_sha256(memory)
        business_after = _business_summary_sha256(memory)
        if schema_before != schema_after or business_before != business_after:
            raise ExactRuntimeCanaryLiveObserverError(
                "controller consistent view VACUUM 改变语义"
            )
        raw = memory.serialize()
        integrity = tuple(row[0] for row in memory.execute("PRAGMA integrity_check"))
        quick = tuple(row[0] for row in memory.execute("PRAGMA quick_check"))
        foreign = tuple(memory.execute("PRAGMA foreign_key_check"))
    except (OSError, sqlite3.Error) as error:
        if memory is not None:
            memory.close()
            memory = None
        raise ExactRuntimeCanaryLiveObserverError(
            "controller 无法形成 SQLite consistent view"
        ) from error
    except BaseException:
        if memory is not None:
            memory.close()
            memory = None
        raise
    finally:
        if source is not None:
            source.close()
    if memory is None:
        raise ExactRuntimeCanaryLiveObserverError(
            "controller consistent view 未建立"
        )
    if integrity != ("ok",) or quick != ("ok",) or foreign:
        memory.close()
        raise ExactRuntimeCanaryLiveObserverError(
            "controller SQLite integrity/foreign-key 复验失败"
        )
    return memory, {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema_sha256": schema_after,
        "business_summary_sha256": business_after,
    }


def _verify_database_paths(
    *,
    base: Path,
    request: ExactRuntimeCanaryRequest,
    evidence: ExactRuntimeCanaryEvidence,
    initial_workspace_node: tuple[str, int],
    initial_snapshots: Mapping[str, Mapping[str, object]] | None = None,
) -> tuple[_DatabaseVerification, ...]:
    """私有 test seam；产品 observer 不接受 base/path。"""

    if not isinstance(base, Path) or not base.is_dir():
        raise ExactRuntimeCanaryLiveObserverError("canary database base 无效")
    if type(request) is not ExactRuntimeCanaryRequest:
        raise ExactRuntimeCanaryLiveObserverError("canary request 不是 exact type")
    if type(evidence) is not ExactRuntimeCanaryEvidence:
        raise ExactRuntimeCanaryLiveObserverError("canary evidence 不是 exact type")
    request_document = request.as_dict()
    evidence_document = evidence.as_dict()
    if evidence_document["request_sha256"] != request.request_sha256:
        raise ExactRuntimeCanaryLiveObserverError("result 未绑定 request")
    challenge_nonce = str(evidence_document["challenge_nonce"])
    results: list[_DatabaseVerification] = []
    for name, request_database, result_database in zip(
        _DATABASE_ORDER,
        request_document["databases"],
        evidence_document["databases"],
        strict=True,
    ):
        if (
            request_database["database_name"] != name
            or result_database["database_name"] != name
        ):
            raise ExactRuntimeCanaryLiveObserverError(
                "canary database order/name 漂移"
            )
        if initial_snapshots is not None:
            initial = initial_snapshots.get(name)
            if type(initial) is not dict or {
                "bytes": result_database["initial_consistent_bytes"],
                "sha256": result_database["initial_consistent_sha256"],
                "schema_sha256": result_database["initial_schema_sha256"],
                "business_summary_sha256": result_database[
                    "initial_business_summary_sha256"
                ],
            } != dict(initial):
                raise ExactRuntimeCanaryLiveObserverError(
                    f"{name} initial consistent/schema/business 未绑定 POST 前现场"
                )
        path = base / _DATABASE_FILES[name]
        sidecars = tuple(
            candidate.name
            for candidate in (
                Path(str(path) + "-wal"),
                Path(str(path) + "-shm"),
                Path(str(path) + "-journal"),
            )
            if candidate.exists()
        )
        if sidecars or result_database["final_members"] != ["main"]:
            raise ExactRuntimeCanaryLiveObserverError(
                f"{name} controller checkpoint 存在 SQLite sidecar"
            )
        memory, snapshot = _consistent_snapshot(path)
        with closing(memory):
            expected = {
                "bytes": result_database["final_consistent_bytes"],
                "sha256": result_database["final_consistent_sha256"],
                "schema_sha256": result_database["final_schema_sha256"],
                "business_summary_sha256": result_database[
                    "final_business_summary_sha256"
                ],
            }
            if snapshot != expected:
                raise ExactRuntimeCanaryLiveObserverError(
                    f"{name} final consistent/schema/business 复验漂移"
                )
            challenge = result_database["challenge"]
            if type(challenge) is not dict:
                raise ExactRuntimeCanaryLiveObserverError(
                    f"{name} challenge structure 漂移"
                )
            challenge_id = str(challenge["challenge_id"])
            _verify_challenge(memory, challenge_id=challenge_id)
            suffix = hashlib.sha256(
                f"{request.request_sha256}:{challenge_nonce}:{name}".encode(
                    "utf-8"
                )
            ).hexdigest()[:20]
            if name == "comments":
                _verify_archive_business(memory, suffix=suffix)
            else:
                _verify_workspace_business(
                    memory,
                    suffix=suffix,
                    initial_node=initial_workspace_node,
                )
        results.append(
            _DatabaseVerification(
                database_name=name,
                final_consistent_bytes=int(snapshot["bytes"]),
                final_consistent_sha256=str(snapshot["sha256"]),
                final_schema_sha256=str(snapshot["schema_sha256"]),
                final_business_summary_sha256=str(
                    snapshot["business_summary_sha256"]
                ),
            )
        )
    return tuple(results)


def _sha256_document(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _database_base(canary: LockedExactRuntimeCanaryInput) -> Path:
    if type(canary) is not LockedExactRuntimeCanaryInput:
        raise ExactRuntimeCanaryLiveObserverError(
            "live observer 只接受 exact canary input"
        )
    request = canary.request.as_dict()
    root = canary._runtime._root  # noqa: SLF001 - 同包 process-local capability。
    bases: set[Path] = set()
    for name, item in zip(_DATABASE_ORDER, request["databases"], strict=True):
        if type(item) is not dict or item.get("database_name") != name:
            raise ExactRuntimeCanaryLiveObserverError(
                "canary request database order 漂移"
            )
        relative = item.get("relative_path")
        if type(relative) is not str:
            raise ExactRuntimeCanaryLiveObserverError(
                "canary request relative path 无效"
            )
        parts = PurePosixPath(relative).parts
        if (
            not parts
            or PurePosixPath(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ExactRuntimeCanaryLiveObserverError(
                "canary request relative path 不是 closed D-root path"
            )
        declared = root.joinpath(*parts)
        guard = canary._mutable[name]  # noqa: SLF001 - 绑定同一 creator guard。
        actual = guard._workspace._target(  # noqa: SLF001
            guard._relative_parts  # noqa: SLF001
        )
        if declared != actual or declared.name != _DATABASE_FILES[name]:
            raise ExactRuntimeCanaryLiveObserverError(
                "canary request 声明路径与 creator-guard 实体路径不同"
            )
        bases.add(declared.parent)
    if len(bases) != 1:
        raise ExactRuntimeCanaryLiveObserverError(
            "两个 canary database 不属于同一固定 state 目录"
        )
    return next(iter(bases))


def _capture_initial_database_state(
    *, base: Path, request: ExactRuntimeCanaryRequest
) -> tuple[dict[str, dict[str, object]], tuple[str, int]]:
    request_document = request.as_dict()
    snapshots: dict[str, dict[str, object]] = {}
    workspace_node: tuple[str, int] | None = None
    for name, request_database in zip(
        _DATABASE_ORDER, request_document["databases"], strict=True
    ):
        memory, snapshot = _consistent_snapshot(base / _DATABASE_FILES[name])
        with closing(memory):
            if {
                "bytes": request_database["initial_consistent_bytes"],
                "sha256": request_database["initial_consistent_sha256"],
            } != {
                "bytes": snapshot["bytes"],
                "sha256": snapshot["sha256"],
            }:
                raise ExactRuntimeCanaryLiveObserverError(
                    f"{name} POST 前 consistent view 未绑定 request"
                )
            snapshots[name] = dict(snapshot)
            if name == "research_workspace":
                rows = _exact_rows(
                    memory,
                    "SELECT node_id,revision FROM research_workspace_node "
                    "ORDER BY node_id LIMIT 1",
                )
                if (
                    len(rows) != 1
                    or type(rows[0][0]) is not str
                    or type(rows[0][1]) is not int
                    or int(rows[0][1]) < 0
                ):
                    raise ExactRuntimeCanaryLiveObserverError(
                        "Workspace POST 前 node/revision 不闭合"
                    )
                workspace_node = (str(rows[0][0]), int(rows[0][1]))
    if workspace_node is None:
        raise ExactRuntimeCanaryLiveObserverError(
            "Workspace POST 前 node identity 缺失"
        )
    return snapshots, workspace_node


def _request_identity(
    document: Mapping[str, object], request: ExactRuntimeCanaryRequest
) -> None:
    expected = request.as_dict()
    for field in (
        "attempt_id",
        "nonce",
        "operation",
        "role",
        "start_nonce",
        "state_identity_sha256",
        "release",
    ):
        if document.get(field) != expected[field]:
            raise ExactRuntimeCanaryLiveObserverError(
                f"live observation.{field} 未绑定 canary request"
            )


def _endpoint_stable_document(
    evidence: WindowsEndpointObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not WindowsEndpointObservationEvidence:
        raise ExactRuntimeCanaryLiveObserverError(
            "endpoint evidence 不是 exact typed evidence"
        )
    document = evidence.as_dict()
    probe = document.get("probe")
    if type(probe) is not dict or type(probe.get("response")) is not dict:
        raise ExactRuntimeCanaryLiveObserverError(
            "endpoint evidence probe/response 结构漂移"
        )
    response = probe["response"]
    return {
        "scm_process_evidence_sha256": document.get(
            "scm_process_evidence_sha256"
        ),
        "attempt_id": document.get("attempt_id"),
        "nonce": document.get("nonce"),
        "operation": document.get("operation"),
        "role": document.get("role"),
        "start_nonce": document.get("start_nonce"),
        "state_identity_sha256": document.get("state_identity_sha256"),
        "release": document.get("release"),
        "listener_before": document.get("listener_before"),
        "listener_after": document.get("listener_after"),
        "writer_lease": response.get("writer_lease"),
    }


def _writer_stable_document(
    evidence: WindowsWriterLeaseObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not WindowsWriterLeaseObservationEvidence:
        raise ExactRuntimeCanaryLiveObserverError(
            "writer evidence 不是 exact typed evidence"
        )
    document = evidence.as_dict()
    return {
        "scm_process_evidence_sha256": document.get(
            "scm_process_evidence_sha256"
        ),
        "attempt_id": document.get("attempt_id"),
        "nonce": document.get("nonce"),
        "operation": document.get("operation"),
        "role": document.get("role"),
        "start_nonce": document.get("start_nonce"),
        "state_identity_sha256": document.get("state_identity_sha256"),
        "release": document.get("release"),
        "lease_record": document.get("lease_record"),
        "kernel_lock_observation": document.get("kernel_lock_observation"),
    }


def _lease_claim_from_writer(
    evidence: WindowsWriterLeaseObservationEvidence,
) -> dict[str, object]:
    document = evidence.as_dict()
    record = document.get("lease_record")
    if type(record) is not dict:
        raise ExactRuntimeCanaryLiveObserverError(
            "writer lease record 结构漂移"
        )
    return {
        "lease_id": record.get("lease_id"),
        "lease_nonce": record.get("lease_nonce"),
        "lease_epoch": record.get("lease_epoch"),
        "lease_record_sha256": record.get("lease_record_sha256"),
        "authority": "claim_not_independently_observed",
    }


def _live_chain(
    *,
    request: ExactRuntimeCanaryRequest,
    scm: LockedWindowsScmProcessObservation,
    endpoint: LockedWindowsEndpointObservation,
    writer: LockedWindowsWriterLeaseObservation,
) -> tuple[dict[str, str], dict[str, object]]:
    if (
        type(scm) is not LockedWindowsScmProcessObservation
        or type(endpoint) is not LockedWindowsEndpointObservation
        or type(writer) is not LockedWindowsWriterLeaseObservation
        or endpoint._scm_observation is not scm  # noqa: SLF001
        or writer._scm is not scm  # noqa: SLF001
        or writer._endpoint is not endpoint  # noqa: SLF001
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "SCM/endpoint/writer 不是同一 exact live child 链"
        )
    scm_evidence = scm.build_evidence()
    endpoint_evidence = endpoint.build_evidence()
    writer_evidence = writer.build_evidence()
    if type(scm_evidence) is not WindowsScmProcessObservationEvidence:
        raise ExactRuntimeCanaryLiveObserverError(
            "SCM evidence 不是 exact typed evidence"
        )
    scm_document = scm_evidence.as_dict()
    endpoint_document = endpoint_evidence.as_dict()
    writer_document = writer_evidence.as_dict()
    for document in (scm_document, endpoint_document, writer_document):
        _request_identity(document, request)
    expected = request.as_dict()
    if (
        scm_document.get("authorization_sha256")
        != expected["authorization_sha256"]
        or scm_document.get("scm_identity_sha256")
        != expected["scm_identity_sha256"]
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "SCM evidence 未绑定 request authorization/identity"
        )
    record = writer_document.get("lease_record")
    if (
        type(record) is not dict
        or record.get("authorization_sha256")
        != expected["authorization_sha256"]
        or record.get("scm_identity_sha256")
        != expected["scm_identity_sha256"]
    ):
        raise ExactRuntimeCanaryLiveObserverError(
            "writer lease record 未绑定 request authorization/SCM identity"
        )
    stable = {
        "scm": hashlib.sha256(scm_evidence.canonical_bytes()).hexdigest(),
        "endpoint": _sha256_document(
            _endpoint_stable_document(endpoint_evidence)
        ),
        "writer": _sha256_document(_writer_stable_document(writer_evidence)),
    }
    return stable, _lease_claim_from_writer(writer_evidence)


def _source_seal_hashes(
    canary: LockedExactRuntimeCanaryInput,
) -> dict[str, str]:
    return {
        name: canary.source_seal(name).seal_sha256
        for name in _DATABASE_ORDER
    }


def _tooling_stable_sha256(
    tooling: LockedExactRuntimeControllerToolingObservation,
) -> str:
    if type(tooling) is not LockedExactRuntimeControllerToolingObservation:
        raise ExactRuntimeCanaryLiveObserverError(
            "controller tooling 不是 exact live capability"
        )
    try:
        evidence = tooling.build_evidence()
    except ExactRuntimeControllerToolingObserverError as error:
        raise ExactRuntimeCanaryLiveObserverError(
            "controller tooling live checkpoint 失败"
        ) from error
    if type(evidence) is not ExactRuntimeControllerToolingObservationEvidence:
        raise ExactRuntimeCanaryLiveObserverError(
            "controller tooling 未返回 exact typed evidence"
        )
    document = evidence.as_dict()
    stable = {
        field: document.get(field)
        for field in (
            "tooling_sha256",
            "manifest_sha256",
            "package_inventory_sha256",
            "python_sha256",
            "service_host_sha256",
        )
    }
    if any(type(value) is not str for value in stable.values()):
        raise ExactRuntimeCanaryLiveObserverError(
            "controller tooling stable identity 结构漂移"
        )
    return _sha256_document(stable)


def _observation_document(
    *,
    request: ExactRuntimeCanaryRequest,
    result: ExactRuntimeCanaryEvidence,
    stable: Mapping[str, str],
    tooling_stable_sha256: str,
    source_seals: Mapping[str, str],
    databases: tuple[_DatabaseVerification, ...],
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": _LIVE_OBSERVATION_SCHEMA,
        "scope": _LIVE_OBSERVATION_SCOPE,
        "request_sha256": request.request_sha256,
        "result_evidence_sha256": result.evidence_sha256,
        "challenge_nonce": result.as_dict()["challenge_nonce"],
        "scm_stable_sha256": stable["scm"],
        "endpoint_stable_sha256": stable["endpoint"],
        "writer_stable_sha256": stable["writer"],
        "controller_tooling_stable_sha256": tooling_stable_sha256,
        "production_state_source_seals": [
            {"database_name": name, "seal_sha256": source_seals[name]}
            for name in _DATABASE_ORDER
        ],
        "databases": [database.as_dict() for database in databases],
        "result": "live_observed_not_formally_qualified",
    }
    document["evidence_sha256"] = _sha256_document(document)
    return document


class LockedExactRuntimeCanaryObservation:
    """HTTP、同链 live identity 与两个真实 SQLite 共同支撑的现场能力。"""

    __slots__ = (
        "_sealed",
        "_state",
        "_canary",
        "_scm",
        "_endpoint",
        "_writer",
        "_tooling",
        "_transport",
        "_base",
        "_initial_snapshots",
        "_initial_workspace_node",
        "_source_seals",
        "_stable",
        "_tooling_stable_sha256",
        "_result_raw",
        "_qualification",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("live canary observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("live canary observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        canary: LockedExactRuntimeCanaryInput,
        scm: LockedWindowsScmProcessObservation,
        endpoint: LockedWindowsEndpointObservation,
        writer: LockedWindowsWriterLeaseObservation,
        tooling: LockedExactRuntimeControllerToolingObservation,
        transport: ProductionExactRuntimeCanaryTransport,
        base: Path,
        initial_snapshots: Mapping[str, Mapping[str, object]],
        initial_workspace_node: tuple[str, int],
        source_seals: Mapping[str, str],
        stable: Mapping[str, str],
        tooling_stable_sha256: str,
        result: ExactRuntimeCanaryEvidence,
        _construction_token: object,
    ):
        if (
            _construction_token is not _LIVE_OBSERVATION_TOKEN
            or type(canary) is not LockedExactRuntimeCanaryInput
            or type(scm) is not LockedWindowsScmProcessObservation
            or type(endpoint) is not LockedWindowsEndpointObservation
            or type(writer) is not LockedWindowsWriterLeaseObservation
            or type(tooling) is not LockedExactRuntimeControllerToolingObservation
            or type(transport) is not ProductionExactRuntimeCanaryTransport
            or type(result) is not ExactRuntimeCanaryEvidence
            or type(tooling_stable_sha256) is not str
        ):
            raise TypeError("live canary observation provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._state = "live"
        self._canary = canary
        self._scm = scm
        self._endpoint = endpoint
        self._writer = writer
        self._tooling = tooling
        self._transport = transport
        self._base = base
        self._initial_snapshots = {
            name: dict(initial_snapshots[name]) for name in _DATABASE_ORDER
        }
        self._initial_workspace_node = initial_workspace_node
        self._source_seals = dict(source_seals)
        self._stable = dict(stable)
        self._tooling_stable_sha256 = tooling_stable_sha256
        self._result_raw = result.canonical_bytes()
        self._qualification: object | None = None
        canary._register_live_observation(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("live canary observation is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _result(self) -> ExactRuntimeCanaryEvidence:
        try:
            return parse_exact_runtime_canary_evidence_bytes(
                self._result_raw, request=self._canary.request
            )
        except ExactRuntimeCanaryEvidenceError as error:
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary frozen result 损坏"
            ) from error

    def _assert_live(self) -> ExactRuntimeCanaryLiveObservationEvidence:
        if self._state != "live":
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation 已撤销"
            )
        self._canary.checkpoint_live()
        if _source_seal_hashes(self._canary) != self._source_seals:
            raise ExactRuntimeCanaryLiveObserverError(
                "production state source seal 漂移"
            )
        tooling_before = _tooling_stable_sha256(self._tooling)
        if tooling_before != self._tooling_stable_sha256:
            raise ExactRuntimeCanaryLiveObserverError(
                "controller tooling stable identity 漂移"
            )
        stable_before, lease_claim_before = _live_chain(
            request=self._canary.request,
            scm=self._scm,
            endpoint=self._endpoint,
            writer=self._writer,
        )
        if stable_before != self._stable:
            raise ExactRuntimeCanaryLiveObserverError(
                "SCM/endpoint/writer stable identity 漂移"
            )
        result = self._result()
        if result.as_dict()["writer_lease_claim"] != lease_claim_before:
            raise ExactRuntimeCanaryLiveObserverError(
                "canary result writer lease claim 与 live observation 不同"
            )
        databases = _verify_database_paths(
            base=self._base,
            request=self._canary.request,
            evidence=result,
            initial_workspace_node=self._initial_workspace_node,
            initial_snapshots=self._initial_snapshots,
        )
        self._canary.checkpoint_live()
        stable_after, lease_claim_after = _live_chain(
            request=self._canary.request,
            scm=self._scm,
            endpoint=self._endpoint,
            writer=self._writer,
        )
        tooling_after = _tooling_stable_sha256(self._tooling)
        if (
            stable_after != stable_before
            or stable_after != self._stable
            or lease_claim_after != lease_claim_before
            or _source_seal_hashes(self._canary) != self._source_seals
            or tooling_after != tooling_before
            or tooling_after != self._tooling_stable_sha256
        ):
            raise ExactRuntimeCanaryLiveObserverError(
                "数据库复验前后 live child/state identity 漂移"
            )
        document = _observation_document(
            request=self._canary.request,
            result=result,
            stable=self._stable,
            tooling_stable_sha256=self._tooling_stable_sha256,
            source_seals=self._source_seals,
            databases=databases,
        )
        return ExactRuntimeCanaryLiveObservationEvidence(
            canonical_bytes(document)
        )

    @property
    def scope(self) -> str:
        self._assert_live()
        return _LIVE_OBSERVATION_SCOPE

    def build_evidence(self) -> ExactRuntimeCanaryLiveObservationEvidence:
        return self._assert_live()

    def _register_qualification(self, qualification: object) -> None:
        from .local_runtime_qualification import LockedLocalRuntimeQualification

        if (
            self._state != "live"
            or type(qualification) is not LockedLocalRuntimeQualification
            or qualification._observation is not self  # noqa: SLF001
            or qualification._state != "live"  # noqa: SLF001
            or self._qualification is not None
        ):
            raise ExactRuntimeCanaryLiveObserverError(
                "formal qualification 不属于当前 live observation"
            )
        object.__setattr__(self, "_qualification", qualification)

    def _release_qualification(self, qualification: object) -> None:
        if qualification is not self._qualification:
            raise ExactRuntimeCanaryLiveObserverError(
                "formal qualification release identity 漂移"
            )
        if getattr(qualification, "_state", None) not in {"closed", "consumed"}:
            raise ExactRuntimeCanaryLiveObserverError(
                "formal qualification 尚未关闭或消费"
            )
        object.__setattr__(self, "_qualification", None)

    def _close_qualification_public(self, qualification: object) -> None:
        if qualification is not self._qualification:
            if getattr(qualification, "_state", None) in {"closed", "consumed"}:
                return
            raise ExactRuntimeCanaryLiveObserverError(
                "formal qualification 不属于当前 observation"
            )
        qualification._close_from_observation(self)

    def close(self) -> None:
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation close 结果已不可判定"
            )
        self._canary._close_live_observation_public(self)  # noqa: SLF001

    def _close_from_canary(self, canary: LockedExactRuntimeCanaryInput) -> None:
        if canary is not self._canary:
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation close owner 漂移"
            )
        if self._state == "closed":
            canary._release_live_observation(self)  # noqa: SLF001
            return
        if self._state == "owner_crash_only":
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation tooling close 结果已不可判定"
            )
        if self._qualification is not None:
            self._qualification._close_from_observation(self)
        if self._qualification is not None:
            raise ExactRuntimeCanaryLiveObserverError(
                "formal qualification 未先于 live observation 闭合"
            )
        object.__setattr__(self, "_state", "closing")
        try:
            self._tooling.close()
        except ExactRuntimeControllerToolingObserverError as error:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation tooling close 结果不明"
            ) from error
        object.__setattr__(self, "_state", "closed")
        canary._release_live_observation(self)  # noqa: SLF001

    def __enter__(self) -> "LockedExactRuntimeCanaryObservation":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionExactRuntimeCanaryLiveObserver:
    """无参 exact-D e.4.2 observer；唯一网络动作是 fixed transport POST。"""

    __slots__ = ("_transport", "_tooling_observer", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production live canary observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production live canary observer 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        transport: ProductionExactRuntimeCanaryTransport,
        tooling_observer: ProductionExactRuntimeControllerToolingObserver,
        _construction_token: object,
    ):
        if (
            _construction_token is not _LIVE_OBSERVER_TOKEN
            or type(transport) is not ProductionExactRuntimeCanaryTransport
            or type(tooling_observer)
            is not ProductionExactRuntimeControllerToolingObserver
        ):
            raise TypeError("production live canary observer provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._transport = transport
        self._tooling_observer = tooling_observer
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production live canary observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionExactRuntimeCanaryLiveObserver":
        return cls(
            transport=ProductionExactRuntimeCanaryTransport.load_exact_d(),
            tooling_observer=(
                ProductionExactRuntimeControllerToolingObserver.load_exact_d()
            ),
            _construction_token=_LIVE_OBSERVER_TOKEN,
        )

    def observe(
        self,
        canary: LockedExactRuntimeCanaryInput,
        scm: LockedWindowsScmProcessObservation,
        endpoint: LockedWindowsEndpointObservation,
        writer: LockedWindowsWriterLeaseObservation,
    ) -> LockedExactRuntimeCanaryObservation:
        if (
            type(self._transport) is not ProductionExactRuntimeCanaryTransport
            or type(self._tooling_observer)
            is not ProductionExactRuntimeControllerToolingObserver
            or type(canary) is not LockedExactRuntimeCanaryInput
        ):
            raise ExactRuntimeCanaryLiveObserverError(
                "product live observer 类型／provenance 漂移"
            )
        begun = False
        tooling: LockedExactRuntimeControllerToolingObservation | None = None
        observation: LockedExactRuntimeCanaryObservation | None = None
        try:
            request = canary.request
            base = _database_base(canary)
            canary.checkpoint_live()
            tooling = self._tooling_observer.observe(canary)
            tooling_stable_before = _tooling_stable_sha256(tooling)
            source_seals = _source_seal_hashes(canary)
            initial_snapshots, initial_workspace_node = (
                _capture_initial_database_state(base=base, request=request)
            )
            stable_before, lease_claim_before = _live_chain(
                request=request,
                scm=scm,
                endpoint=endpoint,
                writer=writer,
            )
            challenge_nonce = secrets.token_hex(24)
            canary._begin_result_observation(self._transport)  # noqa: SLF001
            begun = True
            response = self._transport.post(challenge_nonce)
            if (
                type(response) is not ExactRuntimeCanaryHttpResponse
                or response.status != 200
            ):
                raise ExactRuntimeCanaryLiveObserverError(
                    "fixed transport 未返回 exact 200 response"
                )
            result = parse_exact_runtime_canary_evidence_bytes(
                response.body, request=request
            )
            result_document = result.as_dict()
            if (
                result_document["challenge_nonce"] != challenge_nonce
                or result_document["writer_lease_claim"] != lease_claim_before
            ):
                raise ExactRuntimeCanaryLiveObserverError(
                    "canary HTTP result 未绑定 fresh challenge/live writer"
                )
            canary._commit_result_observation(  # noqa: SLF001
                self._transport, result
            )
            stable_after, lease_claim_after = _live_chain(
                request=request,
                scm=scm,
                endpoint=endpoint,
                writer=writer,
            )
            canary.checkpoint_live()
            tooling_stable_after = _tooling_stable_sha256(tooling)
            if (
                stable_after != stable_before
                or lease_claim_after != lease_claim_before
                or _source_seal_hashes(canary) != source_seals
                or tooling_stable_after != tooling_stable_before
            ):
                raise ExactRuntimeCanaryLiveObserverError(
                    "POST 前后 SCM/endpoint/writer/state identity 漂移"
                )
            observation = LockedExactRuntimeCanaryObservation(
                canary=canary,
                scm=scm,
                endpoint=endpoint,
                writer=writer,
                tooling=tooling,
                transport=self._transport,
                base=base,
                initial_snapshots=initial_snapshots,
                initial_workspace_node=initial_workspace_node,
                source_seals=source_seals,
                stable=stable_after,
                tooling_stable_sha256=tooling_stable_after,
                result=result,
                _construction_token=_LIVE_OBSERVATION_TOKEN,
            )
            observation.build_evidence()
            return observation
        except BaseException as error:
            cleanup_errors: list[BaseException] = []
            try:
                if observation is not None:
                    observation.close()
                elif tooling is not None:
                    tooling.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            if begun:
                try:
                    canary._abort_result_observation(  # noqa: SLF001
                        self._transport
                    )
                except BaseException as abort_error:
                    cleanup_errors.append(abort_error)
            if cleanup_errors:
                raise ExactRuntimeCanaryLiveObserverError(
                    "canary observation 失败且资源／result 状态变为 ambiguous"
                ) from cleanup_errors[0]
            if isinstance(error, ExactRuntimeCanaryLiveObserverError):
                raise
            if isinstance(
                error,
                (ExactRuntimeCanaryTransportError, ExactRuntimeCanaryEvidenceError),
            ):
                raise ExactRuntimeCanaryLiveObserverError(
                    "fixed HTTP/result observation 失败"
                ) from error
            raise ExactRuntimeCanaryLiveObserverError(
                "live canary observation 未闭合"
            ) from error


__all__ = [
    "ExactRuntimeCanaryLiveObservationEvidence",
    "ExactRuntimeCanaryLiveObserverError",
    "LockedExactRuntimeCanaryObservation",
    "ProductionExactRuntimeCanaryLiveObserver",
]
