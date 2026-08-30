"""e.4.1 exact runtime canary 输入的现场、进程内 capability 链。

产品 producer 不接受路径、runtime、seal、copy evidence 或 compatibility document。
它只消费同一 B2 lock epoch 的 transient authorization 与 release closures，并在
现场取得两库 source guard、内存一致视图、CREATE_NEW mutable guard 和 closed
request。持久文档始终只是证据；只有本模块的 live capability 能进入后续观察。
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
import sqlite3
from typing import Mapping, Sequence

from . import local_release_identity as _identity
from .local_deployment_persistence import (
    CrashReleasedFileLock,
    DeploymentLockBusy,
    LocalDeploymentPersistence,
    LockedAttemptWorkspace,
    LockedExactReleaseClosures,
    LockedExactTransientStartAuthorization,
    LockedMutableCanarySqliteSet,
    LockedStateSqliteMemoryView,
    LockedStateSqliteSource,
    StateSqliteMemberObservation,
)
from .local_deployment_runtime import (
    ProductionWindowsDeploymentRuntime,
    TestOnlyWindowsDeploymentRuntimeAdapter,
    _ConnectionInspection,
    _RuntimeCore,
    _inspect_connection,
)
from .local_exact_release_compatibility import (
    DATABASE_ORDER,
    WORKSPACE_MIGRATIONS,
    build_exact_release_compatibility_evidence,
)
from .local_exact_runtime_canary_evidence import (
    EXACT_RUNTIME_CANARY_REQUEST_SCHEMA,
    EXACT_RUNTIME_CANARY_REQUEST_SCOPE,
    ExactRuntimeCanaryEvidence,
    ExactRuntimeCanaryRequest,
    build_exact_runtime_canary_request,
    parse_exact_runtime_canary_evidence_bytes,
)
from .local_runtime_evidence import (
    ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA,
    STATE_DATABASE_SEAL_SCHEMA,
    IsolatedSqliteCopyEvidence,
    StateDatabaseSeal,
    build_isolated_sqlite_copy_evidence,
    build_state_database_seal,
)


_PRODUCER_TOKEN = object()
_TEST_PRODUCER_TOKEN = object()
_INPUT_TOKEN = object()
_DATABASE_FILES = {
    "comments": "comments.sqlite3",
    "research_workspace": "research_workspace.sqlite3",
}
_STATE_OPERATION = {
    "activation": "activate_successor",
    "rollback": "rollback_to_prior",
    "bootstrap_first_pair": "bootstrap_first_pair",
}
_INPUT_SCOPE = "exact_runtime_canary_input_live_only"


class ExactRuntimeCanaryInputError(RuntimeError):
    """e.4.1 现场输入链不能机械闭合时抛出。"""


def _canonical_clone(value: object) -> object:
    return json.loads(_identity.canonical_bytes(value).decode("utf-8"))


def _observation_document(
    observation: StateSqliteMemberObservation,
) -> dict[str, object] | None:
    if observation.presence == "absent":
        return None
    if (
        observation.presence != "present"
        or observation.identity_scheme is None
        or observation.size is None
        or observation.mtime_ns is None
        or observation.bytes_sha256 is None
        or observation.volume_identity_sha256 is None
        or observation.file_identity_sha256 is None
    ):
        raise ExactRuntimeCanaryInputError(
            "state source member observation 不闭合"
        )
    return {
        "identity_scheme": observation.identity_scheme,
        "bytes": observation.size,
        "mtime_ns": observation.mtime_ns,
        "bytes_sha256": observation.bytes_sha256,
        "volume_identity_sha256": observation.volume_identity_sha256,
        "file_identity_sha256": observation.file_identity_sha256,
    }


def _migration_ledger(
    closures: LockedExactReleaseClosures,
    database: str,
) -> list[dict[str, object]]:
    if database == "comments":
        return []
    metadata = closures.metadata()
    roles = metadata.get("roles")
    if not isinstance(roles, Mapping):
        raise ExactRuntimeCanaryInputError("release closure roles metadata 缺失")
    candidate = roles.get("candidate")
    if not isinstance(candidate, Mapping):
        raise ExactRuntimeCanaryInputError("candidate release metadata 缺失")
    migrations = candidate.get("migrations")
    if not isinstance(migrations, list):
        raise ExactRuntimeCanaryInputError("candidate migration closure 缺失")
    by_path: dict[str, Mapping[str, object]] = {}
    for value in migrations:
        if not isinstance(value, Mapping):
            raise ExactRuntimeCanaryInputError("candidate migration entry 类型漂移")
        path = value.get("relative_path")
        if type(path) is not str or path in by_path:
            raise ExactRuntimeCanaryInputError("candidate migration path 不闭合")
        by_path[path] = value
    if tuple(sorted(by_path)) != tuple(sorted(WORKSPACE_MIGRATIONS)):
        raise ExactRuntimeCanaryInputError("candidate migration 集合漂移")
    result: list[dict[str, object]] = []
    for version, name in (
        (1, "research_workspace"),
        (2, "project_semantics"),
        (3, "project_creation_command"),
    ):
        prefix = f"migrations/research_workspace/{version:04d}_{name}"
        down = by_path[prefix + ".down.sql"]
        up = by_path[prefix + ".up.sql"]
        result.append(
            {
                "version": version,
                "name": name,
                "up_sha256": up["sha256"],
                "down_sha256": down["sha256"],
            }
        )
    return result


def _materialize_main(
    view: LockedStateSqliteMemoryView,
    *,
    database: str,
    expected_migration_ledger: list[dict[str, object]],
) -> tuple[bytes, _ConnectionInspection]:
    if type(view) is not LockedStateSqliteMemoryView or view.database != database:
        raise ExactRuntimeCanaryInputError("memory view/database capability 不匹配")
    view._assert_live()
    memory = view._connection
    memory.row_factory = sqlite3.Row
    memory.execute("PRAGMA foreign_keys=ON")
    before = _inspect_connection(
        memory,
        database=database,
        expected_migration_ledger=expected_migration_ledger,
    )
    view.vacuum()
    after = _inspect_connection(
        memory,
        database=database,
        expected_migration_ledger=expected_migration_ledger,
    )
    if before != after:
        raise ExactRuntimeCanaryInputError(
            "main-only materialization 前后 schema/business 语义漂移"
        )
    raw = view.serialize()
    if (
        type(raw) is not bytes
        or len(raw) < 512
        or raw[:16] != b"SQLite format 3\x00"
        or raw[18:20] != b"\x01\x01"
    ):
        raise ExactRuntimeCanaryInputError(
            "materializer 未形成 rollback-journal main-only bytes"
        )
    return raw, before


def _build_source_seal(
    *,
    runtime: _RuntimeCore,
    authorization: LockedExactTransientStartAuthorization,
    source: LockedStateSqliteSource,
    view: LockedStateSqliteMemoryView,
    database: str,
    compatibility_evidence_sha256: str,
    inspection: _ConnectionInspection,
) -> StateDatabaseSeal:
    source.checkpoint_unchanged()
    before = view.before
    after = view.after
    if before != after or tuple(item.label for item in before) != (
        "main",
        "wal",
        "shm",
    ):
        raise ExactRuntimeCanaryInputError("source backup observation 集合漂移")
    database_path = runtime._root / "state" / _DATABASE_FILES[database]
    file_set: list[dict[str, object]] = []
    for before_item, after_item in zip(before, after, strict=True):
        if before_item.label != after_item.label:
            raise ExactRuntimeCanaryInputError("source member 顺序漂移")
        suffix = {"main": "", "wal": "-wal", "shm": "-shm"}[
            before_item.label
        ]
        file_set.append(
            {
                "role": before_item.label,
                "canonical_path": str(database_path) + suffix,
                "presence": before_item.presence,
                "before": _observation_document(before_item),
                "after": _observation_document(after_item),
            }
        )
    payload = {
        "schema_version": STATE_DATABASE_SEAL_SCHEMA,
        "attempt_id": authorization.attempt_id,
        "nonce": authorization.nonce,
        "operation": _STATE_OPERATION[authorization.operation],
        "database_name": database,
        "qualification_scope": "diagnostic_only_unresolved_release_closure",
        "runtime_scope": (
            "test_only_explicit_root" if runtime._test_only else "production_exact_d"
        ),
        "canonical_path": str(database_path),
        "state_identity_sha256": authorization.state_identity_sha256,
        "open_mode": source.mode,
        "raw_user_version": inspection.raw_user_version,
        "logical_schema": inspection.logical_schema,
        "migration_ledger": inspection.migration_ledger,
        "sqlite_schema_sha256": inspection.sqlite_schema_sha256,
        "integrity_check": inspection.integrity_check,
        "quick_check": inspection.quick_check,
        "foreign_key_violation_count": inspection.foreign_key_violation_count,
        "business_summary": inspection.business_summary,
        "file_set": file_set,
        "compatibility_manifest_sha256": compatibility_evidence_sha256,
        "result": "read_only_observation",
    }
    if runtime._test_only:
        document = build_state_database_seal(
            payload, for_test_only_root=str(runtime._root)
        )
        return StateDatabaseSeal.from_test_document(
            document, test_root=str(runtime._root)
        )
    return StateDatabaseSeal.from_document(build_state_database_seal(payload))


def _build_copy_evidence(
    *,
    authorization: LockedExactTransientStartAuthorization,
    database: str,
    compatibility_evidence_sha256: str,
    seal: StateDatabaseSeal,
    raw: bytes,
    inspection: _ConnectionInspection,
) -> IsolatedSqliteCopyEvidence:
    document = build_isolated_sqlite_copy_evidence(
        {
            "schema_version": ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA,
            "attempt_id": authorization.attempt_id,
            "nonce": authorization.nonce,
            "operation": _STATE_OPERATION[authorization.operation],
            "database_name": database,
            "state_identity_sha256": authorization.state_identity_sha256,
            "compatibility_manifest_sha256": compatibility_evidence_sha256,
            "source_seal_sha256": seal.seal_sha256,
            "sqlite_main_bytes": len(raw),
            "sqlite_main_sha256": hashlib.sha256(raw).hexdigest(),
            "destination_members": ["main"],
            "destination_integrity_check": inspection.integrity_check,
            "destination_quick_check": inspection.quick_check,
            "destination_foreign_key_violation_count": (
                inspection.foreign_key_violation_count
            ),
            "destination_schema_sha256": inspection.sqlite_schema_sha256,
            "destination_business_summary_sha256": inspection.business_summary[
                "summary_sha256"
            ],
            "result": "isolated_copy_verified",
        }
    )
    return IsolatedSqliteCopyEvidence.from_document(document)


class LockedExactRuntimeCanaryInput:
    """持有 e.4.1 全部 live upstream 的不可序列化 canary 输入。"""

    __slots__ = (
        "_runtime",
        "_persistence",
        "_lock",
        "_workspace",
        "_authorization",
        "_closures",
        "_sources",
        "_views",
        "_mutable",
        "_source_seals",
        "_copy_evidence",
        "_compatibility_raw",
        "_closure_metadata_raw",
        "_view_sha256",
        "_request",
        "_request_raw",
        "_request_parts",
        "_request_initial",
        "_result_initial",
        "_result_raw",
        "_controller_tooling_observation",
        "_live_observation",
        "_state",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact runtime canary input 不允许派生")

    def __init__(
        self,
        *,
        runtime: _RuntimeCore,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: LockedExactTransientStartAuthorization,
        closures: LockedExactReleaseClosures,
        sources: Mapping[str, LockedStateSqliteSource],
        views: Mapping[str, LockedStateSqliteMemoryView],
        mutable: Mapping[str, LockedMutableCanarySqliteSet],
        source_seals: Mapping[str, StateDatabaseSeal],
        copy_evidence: Mapping[str, IsolatedSqliteCopyEvidence],
        compatibility_documents: Sequence[Mapping[str, object]],
        request: ExactRuntimeCanaryRequest,
        request_parts: tuple[str, ...],
        request_initial: os.stat_result,
        _construction_token: object,
    ):
        if _construction_token is not _INPUT_TOKEN:
            raise DeploymentLockBusy(
                "exact runtime canary input 必须由 product producer 构造"
            )
        self._runtime = runtime
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._authorization = authorization
        self._closures = closures
        self._sources = dict(sources)
        self._views = dict(views)
        self._mutable = dict(mutable)
        self._source_seals = dict(source_seals)
        self._copy_evidence = dict(copy_evidence)
        self._compatibility_raw = tuple(
            _identity.canonical_bytes(document)
            for document in compatibility_documents
        )
        self._closure_metadata_raw = _identity.canonical_bytes(
            closures.metadata()
        )
        self._view_sha256 = {
            name: hashlib.sha256(view.serialize()).hexdigest()
            for name, view in self._views.items()
        }
        self._request = request
        self._request_raw = request.canonical_bytes()
        self._request_parts = request_parts
        self._request_initial = request_initial
        self._result_initial: os.stat_result | None = None
        self._result_raw: bytes | None = None
        self._controller_tooling_observation: object | None = None
        self._live_observation: object | None = None
        self._state = "live"

    def __reduce__(self) -> object:
        raise TypeError("exact runtime canary input is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _checkpoint_request(self) -> None:
        observed = self._workspace._preflight_parts(
            self._request_parts,
            expected_kind="file",
            allow_absent=False,
        )
        if (
            observed is None
            or (observed.st_dev, observed.st_ino)
            != (self._request_initial.st_dev, self._request_initial.st_ino)
            or observed.st_size != self._request_initial.st_size
            or observed.st_mtime_ns != self._request_initial.st_mtime_ns
            or getattr(observed, "st_nlink", 1) != 1
        ):
            raise ExactRuntimeCanaryInputError("canary request file identity 漂移")
        target = self._workspace._target(self._request_parts)
        raw = target.read_bytes()
        confirmed = self._workspace._preflight_parts(
            self._request_parts,
            expected_kind="file",
            allow_absent=False,
        )
        if confirmed is None or raw != self._request_raw or (
            confirmed.st_dev,
            confirmed.st_ino,
            confirmed.st_size,
            confirmed.st_mtime_ns,
        ) != (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
        ):
            raise ExactRuntimeCanaryInputError("canary request bytes 读取期间漂移")

    def _checkpoint_layout(self) -> None:
        role = self._authorization.role
        base = self._workspace._target(("runtime-canary", role))
        state = base / "state"
        temporary = base / "tmp"
        expected_base = {"request.json", "state", "tmp"}
        if self._state == "live_result":
            expected_base.add("result.json")
        observed_base = {entry.name for entry in os.scandir(base)}
        observed_state = {entry.name for entry in os.scandir(state)}
        observed_temporary = {entry.name for entry in os.scandir(temporary)}
        if (
            observed_base != expected_base
            or observed_state != set(_DATABASE_FILES.values())
            or observed_temporary
        ):
            self._state = "result_revoked"
            raise ExactRuntimeCanaryInputError(
                "runtime canary request/result/state/tmp namespace 漂移"
            )

    def _checkpoint_result(self) -> None:
        if self._state != "live_result":
            return
        try:
            initial = self._result_initial
            expected_raw = self._result_raw
            if initial is None or expected_raw is None:
                raise ExactRuntimeCanaryInputError("canary result lifecycle 未闭合")
            parts = (
                "runtime-canary",
                self._authorization.role,
                "result.json",
            )
            observed = self._workspace._preflight_parts(
                parts, expected_kind="file", allow_absent=False
            )
            if (
                observed is None
                or (observed.st_dev, observed.st_ino)
                != (initial.st_dev, initial.st_ino)
                or observed.st_size != initial.st_size
                or observed.st_mtime_ns != initial.st_mtime_ns
                or getattr(observed, "st_nlink", 1) != 1
            ):
                raise ExactRuntimeCanaryInputError(
                    "canary result file identity 漂移"
                )
            raw = self._workspace._target(parts).read_bytes()
            confirmed = self._workspace._preflight_parts(
                parts, expected_kind="file", allow_absent=False
            )
            if confirmed is None or raw != expected_raw or (
                confirmed.st_dev,
                confirmed.st_ino,
                confirmed.st_size,
                confirmed.st_mtime_ns,
            ) != (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
                observed.st_mtime_ns,
            ):
                raise ExactRuntimeCanaryInputError(
                    "canary result bytes 读取期间漂移"
                )
            parsed = parse_exact_runtime_canary_evidence_bytes(
                raw, request=self._request
            )
            if parsed.canonical_bytes() != expected_raw:
                raise ExactRuntimeCanaryInputError(
                    "canary result canonical bytes 漂移"
                )
        except BaseException:
            self._state = "result_revoked"
            raise

    def _assert_live(self) -> None:
        if self._state not in {"live", "live_result"}:
            raise ExactRuntimeCanaryInputError("exact runtime canary input 已关闭")
        if self._live_observation is not None and getattr(
            self._live_observation, "_state", None
        ) != "live":
            raise ExactRuntimeCanaryInputError(
                "exact runtime canary live observation 已失效"
            )
        if self._controller_tooling_observation is not None and getattr(
            self._controller_tooling_observation, "_state", None
        ) != "live":
            raise ExactRuntimeCanaryInputError(
                "controller tooling observation 已失效"
            )
        self._persistence.assert_global_lock(self._lock)
        self._workspace._assert_live()
        if (
            self._authorization._workspace is not self._workspace
            or self._closures._workspace is not self._workspace
            or self._closures._lock is not self._lock
        ):
            raise DeploymentLockBusy("canary input upstream epoch/owner 漂移")
        # 每次从 live closures 重建，不保存或信任旧 evidence capability。
        compatibility = build_exact_release_compatibility_evidence(self._closures)
        current_raw = tuple(
            _identity.canonical_bytes(document)
            for document in compatibility.documents
        )
        if (
            current_raw != self._compatibility_raw
            or _identity.canonical_bytes(self._closures.metadata())
            != self._closure_metadata_raw
        ):
            raise ExactRuntimeCanaryInputError("release compatibility/closure 漂移")
        for name in DATABASE_ORDER:
            source = self._sources[name]
            view = self._views[name]
            mutable = self._mutable[name]
            source.checkpoint_unchanged()
            if (
                view.database != name
                or hashlib.sha256(view.serialize()).hexdigest()
                != self._view_sha256[name]
            ):
                raise ExactRuntimeCanaryInputError("state memory view 漂移")
            mutable.checkpoint_closed()
        self._checkpoint_request()
        self._checkpoint_result()
        self._checkpoint_layout()

    @staticmethod
    def _assert_result_observer(owner: object) -> None:
        # 局部导入避免 observer 顶层反向依赖；只有无参 exact-D transport
        # 能进入这条私有、单向生命周期 seam，persistent result 无法自授。
        from .local_exact_runtime_canary_observer import (
            ProductionExactRuntimeCanaryTransport,
        )

        if type(owner) is not ProductionExactRuntimeCanaryTransport:
            raise ExactRuntimeCanaryInputError(
                "canary result lifecycle 拒绝非产品 observation owner"
            )

    def _begin_result_observation(self, owner: object) -> None:
        self._assert_result_observer(owner)
        self._assert_live()
        if self._state != "live":
            raise ExactRuntimeCanaryInputError("canary result observation 不得重放")
        parts = (
            "runtime-canary",
            self._authorization.role,
            "result.json",
        )
        if self._workspace._preflight_parts(
            parts, expected_kind="file", allow_absent=True
        ) is not None:
            raise ExactRuntimeCanaryInputError(
                "canary result 必须在 observation 前保持 absent"
            )
        self._state = "result_pending"

    def _commit_result_observation(
        self,
        owner: object,
        evidence: ExactRuntimeCanaryEvidence,
    ) -> None:
        self._assert_result_observer(owner)
        if self._state != "result_pending":
            raise ExactRuntimeCanaryInputError("canary result observation phase 漂移")
        if type(evidence) is not ExactRuntimeCanaryEvidence:
            self._state = "result_revoked"
            raise ExactRuntimeCanaryInputError(
                "canary result 必须是同 request 的 typed evidence"
            )
        raw = evidence.canonical_bytes()
        try:
            parsed = parse_exact_runtime_canary_evidence_bytes(
                raw, request=self._request
            )
            if parsed.canonical_bytes() != raw:
                raise ExactRuntimeCanaryInputError(
                    "canary result typed evidence bytes 漂移"
                )
            parts = (
                "runtime-canary",
                self._authorization.role,
                "result.json",
            )
            observed = self._workspace._preflight_parts(
                parts, expected_kind="file", allow_absent=False
            )
            if observed is None or getattr(observed, "st_nlink", 1) != 1:
                raise ExactRuntimeCanaryInputError("canary result publish 未闭合")
            if self._workspace._target(parts).read_bytes() != raw:
                raise ExactRuntimeCanaryInputError(
                    "HTTP typed result 与固定 result.json 不同"
                )
            confirmed = self._workspace._preflight_parts(
                parts, expected_kind="file", allow_absent=False
            )
            if confirmed is None or (
                confirmed.st_dev,
                confirmed.st_ino,
                confirmed.st_size,
                confirmed.st_mtime_ns,
            ) != (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
                observed.st_mtime_ns,
            ):
                raise ExactRuntimeCanaryInputError(
                    "canary result publish 读取期间漂移"
                )
            self._result_initial = confirmed
            self._result_raw = raw
            self._state = "live_result"
            self._assert_live()
        except BaseException:
            self._state = "result_revoked"
            raise

    def _abort_result_observation(self, owner: object) -> None:
        self._assert_result_observer(owner)
        if self._state != "result_pending":
            return
        parts = (
            "runtime-canary",
            self._authorization.role,
            "result.json",
        )
        if self._workspace._preflight_parts(
            parts, expected_kind="file", allow_absent=True
        ) is not None:
            self._state = "result_revoked"
            raise ExactRuntimeCanaryInputError(
                "失败 observation 已出现 ambiguous result"
            )
        self._state = "live"
        self._assert_live()

    @property
    def scope(self) -> str:
        self._assert_live()
        return _INPUT_SCOPE

    @property
    def request(self) -> ExactRuntimeCanaryRequest:
        self._assert_live()
        return self._request

    @property
    def request_sha256(self) -> str:
        self._assert_live()
        return self._request.request_sha256

    def source_seal(self, database: str) -> StateDatabaseSeal:
        self._assert_live()
        if type(database) is not str or database not in DATABASE_ORDER:
            raise ExactRuntimeCanaryInputError("database 不属于固定枚举")
        return self._source_seals[database]

    def copy_evidence(self, database: str) -> IsolatedSqliteCopyEvidence:
        self._assert_live()
        if type(database) is not str or database not in DATABASE_ORDER:
            raise ExactRuntimeCanaryInputError("database 不属于固定枚举")
        return self._copy_evidence[database]

    def checkpoint_live(self) -> None:
        self._assert_live()

    def _register_controller_tooling_observation(
        self, observation: object
    ) -> None:
        from .local_exact_runtime_controller_tooling_observer import (
            LockedExactRuntimeControllerToolingObservation,
        )

        if (
            self._state not in {"live", "live_result"}
            or type(observation)
            is not LockedExactRuntimeControllerToolingObservation
            or observation._canary is not self
            or observation._state != "prepared"
        ):
            raise ExactRuntimeCanaryInputError(
                "controller tooling observation 不属于当前 canary input"
            )
        if self._controller_tooling_observation is not None:
            raise ExactRuntimeCanaryInputError(
                "canary input 只允许一个 controller tooling observation"
            )
        self._controller_tooling_observation = observation

    def _release_controller_tooling_observation(
        self, observation: object
    ) -> None:
        if observation is not self._controller_tooling_observation:
            raise ExactRuntimeCanaryInputError(
                "controller tooling release identity 漂移"
            )
        if getattr(observation, "_state", None) != "closed":
            raise ExactRuntimeCanaryInputError(
                "controller tooling observation 未机械闭合"
            )
        self._controller_tooling_observation = None

    def _close_controller_tooling_observation_public(
        self, observation: object
    ) -> None:
        if observation is not self._controller_tooling_observation:
            if getattr(observation, "_state", None) == "closed":
                return
            raise ExactRuntimeCanaryInputError(
                "controller tooling observation 不属于当前 input"
            )
        observation._close_from_canary(self)

    def _register_live_observation(self, observation: object) -> None:
        """Bind the one e.4.2 dependent without a top-level reverse import."""

        from .local_exact_runtime_canary_live_observer import (
            LockedExactRuntimeCanaryObservation,
        )

        if (
            self._state != "live_result"
            or type(observation) is not LockedExactRuntimeCanaryObservation
            or observation._canary is not self
            or observation._state != "live"
            or observation._tooling is not self._controller_tooling_observation
        ):
            raise ExactRuntimeCanaryInputError(
                "live observation 不属于当前 result/input lifecycle"
            )
        if self._live_observation is not None:
            raise ExactRuntimeCanaryInputError(
                "exact runtime canary input 只允许一个 live observation"
            )
        self._live_observation = observation

    def _release_live_observation(self, observation: object) -> None:
        if observation is not self._live_observation:
            raise ExactRuntimeCanaryInputError(
                "live observation release identity 漂移"
            )
        if getattr(observation, "_state", None) != "closed":
            raise ExactRuntimeCanaryInputError(
                "live observation 未机械闭合"
            )
        self._live_observation = None

    def _close_live_observation_public(self, observation: object) -> None:
        if observation is not self._live_observation:
            if getattr(observation, "_state", None) == "closed":
                return
            raise ExactRuntimeCanaryInputError(
                "live observation 不属于当前 canary input"
            )
        observation._close_from_canary(self)

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_runtime_canary_input_public(self)

    def _close_from_workspace(self, workspace: LockedAttemptWorkspace) -> None:
        if workspace is not self._workspace:
            raise DeploymentLockBusy("canary input close workspace authority 漂移")
        if self._state == "closed":
            return
        if self._live_observation is not None:
            self._live_observation._close_from_canary(self)
        if self._live_observation is not None:
            raise ExactRuntimeCanaryInputError(
                "live observation 未先于 canary input 闭合"
            )
        if self._controller_tooling_observation is not None:
            self._controller_tooling_observation._close_from_canary(self)
        if self._controller_tooling_observation is not None:
            raise ExactRuntimeCanaryInputError(
                "controller tooling 未先于 canary input 闭合"
            )
        self._state = "closed"
        workspace._release_runtime_canary_input(self)

    def __enter__(self) -> "LockedExactRuntimeCanaryInput":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


def _produce(
    *,
    runtime: _RuntimeCore,
    persistence: LocalDeploymentPersistence,
    lock: CrashReleasedFileLock,
    workspace: LockedAttemptWorkspace,
    authorization: LockedExactTransientStartAuthorization,
    closures: LockedExactReleaseClosures,
) -> LockedExactRuntimeCanaryInput:
    persistence.assert_global_lock(lock)
    workspace._assert_live()
    if (
        type(persistence) is not LocalDeploymentPersistence
        or type(lock) is not CrashReleasedFileLock
        or type(workspace) is not LockedAttemptWorkspace
        or type(authorization) is not LockedExactTransientStartAuthorization
        or type(closures) is not LockedExactReleaseClosures
        or workspace._lock is not lock
        or authorization._persistence is not persistence
        or authorization._workspace is not workspace
        or closures._persistence is not persistence
        or closures._workspace is not workspace
        or closures._lock is not lock
        or runtime._root != persistence.layout.root
    ):
        raise DeploymentLockBusy(
            "canary input 只接受同 exact runtime/B2 lock/workspace/epoch capability"
        )
    compatibility = build_exact_release_compatibility_evidence(closures)
    if compatibility.aggregate_sha256 != closures.planned_compatibility_sha256:
        raise ExactRuntimeCanaryInputError("compatibility aggregate 漂移")
    compatibility_by_name = {
        name: compatibility.document(name) for name in DATABASE_ORDER
    }
    sources: dict[str, LockedStateSqliteSource] = {}
    views: dict[str, LockedStateSqliteMemoryView] = {}
    mutable: dict[str, LockedMutableCanarySqliteSet] = {}
    source_seals: dict[str, StateDatabaseSeal] = {}
    copy_evidence: dict[str, IsolatedSqliteCopyEvidence] = {}
    raw_by_name: dict[str, bytes] = {}
    canary_input: LockedExactRuntimeCanaryInput | None = None
    try:
        for name in DATABASE_ORDER:
            source = persistence.lock_state_sqlite_source(lock, workspace, name)
            sources[name] = source
            views[name] = source.backup_to_memory()
        persistence.prepare_runtime_canary_layout(
            lock, workspace, authorization
        )
        for name in DATABASE_ORDER:
            compatibility_document = compatibility_by_name[name]
            compatibility_hash = str(
                compatibility_document["evidence_sha256"]
            )
            ledger = _migration_ledger(closures, name)
            raw, inspection = _materialize_main(
                views[name],
                database=name,
                expected_migration_ledger=ledger,
            )
            seal = _build_source_seal(
                runtime=runtime,
                authorization=authorization,
                source=sources[name],
                view=views[name],
                database=name,
                compatibility_evidence_sha256=compatibility_hash,
                inspection=inspection,
            )
            guard = persistence.create_mutable_canary_sqlite(
                lock, workspace, name, raw
            )
            if guard.read_main_bytes() != raw:
                raise ExactRuntimeCanaryInputError(
                    "mutable guard initial main 与 consistent bytes 不同"
                )
            evidence = _build_copy_evidence(
                authorization=authorization,
                database=name,
                compatibility_evidence_sha256=compatibility_hash,
                seal=seal,
                raw=raw,
                inspection=inspection,
            )
            mutable[name] = guard
            source_seals[name] = seal
            copy_evidence[name] = evidence
            raw_by_name[name] = raw
        request_document = build_exact_runtime_canary_request(
            {
                "schema_version": EXACT_RUNTIME_CANARY_REQUEST_SCHEMA,
                "scope": EXACT_RUNTIME_CANARY_REQUEST_SCOPE,
                "attempt_id": authorization.attempt_id,
                "nonce": authorization.nonce,
                "operation": authorization.operation,
                "role": authorization.role,
                "start_nonce": authorization.start_nonce,
                "authorization_sha256": authorization.authorization_sha256,
                "scm_identity_sha256": authorization.scm_identity_sha256,
                "state_identity_sha256": authorization.state_identity_sha256,
                "release": authorization.release_ref,
                "databases": [
                    {
                        "database_name": name,
                        "relative_path": (
                            f"tmp/deployment-attempts/{authorization.attempt_id}-"
                            f"{authorization.nonce}/runtime-canary/"
                            f"{authorization.role}/state/{_DATABASE_FILES[name]}"
                        ),
                        "source_seal_sha256": source_seals[name].seal_sha256,
                        "isolated_copy_evidence_sha256": (
                            copy_evidence[name].evidence_sha256
                        ),
                        "compatibility_evidence_sha256": (
                            compatibility_by_name[name]["evidence_sha256"]
                        ),
                        "initial_consistent_bytes": len(raw_by_name[name]),
                        "initial_consistent_sha256": hashlib.sha256(
                            raw_by_name[name]
                        ).hexdigest(),
                    }
                    for name in DATABASE_ORDER
                ],
            }
        )
        request = ExactRuntimeCanaryRequest.from_document(request_document)
        request_parts = (
            "runtime-canary",
            authorization.role,
            "request.json",
        )
        with workspace.open_new_file("/".join(request_parts)) as target:
            request_raw = request.canonical_bytes()
            if target.write_all(request_raw) != len(request_raw):
                raise ExactRuntimeCanaryInputError("canary request short write")
            target.fsync()
        request_initial = workspace._preflight_parts(
            request_parts, expected_kind="file", allow_absent=False
        )
        if request_initial is None:
            raise ExactRuntimeCanaryInputError("canary request publish 后缺失")
        canary_input = LockedExactRuntimeCanaryInput(
            runtime=runtime,
            persistence=persistence,
            lock=lock,
            workspace=workspace,
            authorization=authorization,
            closures=closures,
            sources=sources,
            views=views,
            mutable=mutable,
            source_seals=source_seals,
            copy_evidence=copy_evidence,
            compatibility_documents=compatibility.documents,
            request=request,
            request_parts=request_parts,
            request_initial=request_initial,
            _construction_token=_INPUT_TOKEN,
        )
        workspace._register_runtime_canary_input(canary_input)
        canary_input.checkpoint_live()
        return canary_input
    except BaseException:
        close_error: BaseException | None = None
        if (
            canary_input is not None
            and canary_input in workspace._runtime_canary_inputs
        ):
            try:
                canary_input.close()
            except BaseException as error:
                close_error = error
        for resource in reversed(tuple(mutable.values())):
            try:
                resource.close()
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for view in reversed(tuple(views.values())):
            try:
                view.close()
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for source in reversed(tuple(sources.values())):
            try:
                source.close()
            except BaseException as error:
                if close_error is None:
                    close_error = error
        if close_error is not None:
            raise ExactRuntimeCanaryInputError(
                "canary input acquisition cleanup 未闭合"
            ) from close_error
        raise


class ProductionExactRuntimeCanaryInputProducer:
    """唯一产品 e.4.1 producer；loader 与 produce 均无路径接缝。"""

    __slots__ = ("_runtime",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("product canary input producer 不允许派生")

    def __init__(
        self,
        runtime: ProductionWindowsDeploymentRuntime,
        *,
        _construction_token: object,
    ):
        if (
            _construction_token is not _PRODUCER_TOKEN
            or type(runtime) is not ProductionWindowsDeploymentRuntime
        ):
            raise ExactRuntimeCanaryInputError(
                "product producer 必须由 load_exact_d 构造"
            )
        self._runtime = runtime

    @classmethod
    def load_exact_d(cls) -> "ProductionExactRuntimeCanaryInputProducer":
        runtime = ProductionWindowsDeploymentRuntime.load_exact_d()
        return cls(runtime, _construction_token=_PRODUCER_TOKEN)

    def produce(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: LockedExactTransientStartAuthorization,
        closures: LockedExactReleaseClosures,
    ) -> LockedExactRuntimeCanaryInput:
        if type(self._runtime) is not ProductionWindowsDeploymentRuntime:
            raise ExactRuntimeCanaryInputError("product runtime type 漂移")
        return _produce(
            runtime=self._runtime._core,
            persistence=persistence,
            lock=lock,
            workspace=workspace,
            authorization=authorization,
            closures=closures,
        )


class _TestOnlyExactRuntimeCanaryInputProducerAdapter:
    """显式测试 adapter；不进入产品导出、CLI、config 或 service entry。"""

    __slots__ = ("_runtime", "_test_token")

    def __init__(
        self,
        runtime: TestOnlyWindowsDeploymentRuntimeAdapter,
        *,
        _test_token: object,
    ):
        if (
            _test_token is not _TEST_PRODUCER_TOKEN
            or type(runtime) is not TestOnlyWindowsDeploymentRuntimeAdapter
        ):
            raise ExactRuntimeCanaryInputError("test producer 构造 authority 无效")
        self._runtime = runtime
        self._test_token = _test_token

    @classmethod
    def for_test_only(
        cls,
        runtime: TestOnlyWindowsDeploymentRuntimeAdapter,
    ) -> "_TestOnlyExactRuntimeCanaryInputProducerAdapter":
        return cls(runtime, _test_token=_TEST_PRODUCER_TOKEN)

    @property
    def scope(self) -> str:
        return "test_only_explicit_runtime_canary_input_producer"

    def produce(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: LockedExactTransientStartAuthorization,
        closures: LockedExactReleaseClosures,
    ) -> LockedExactRuntimeCanaryInput:
        if type(self._runtime) is not TestOnlyWindowsDeploymentRuntimeAdapter:
            raise ExactRuntimeCanaryInputError("test runtime type 漂移")
        return _produce(
            runtime=self._runtime._core,
            persistence=persistence,
            lock=lock,
            workspace=workspace,
            authorization=authorization,
            closures=closures,
        )


__all__ = [
    "ExactRuntimeCanaryInputError",
    "LockedExactRuntimeCanaryInput",
    "ProductionExactRuntimeCanaryInputProducer",
]
