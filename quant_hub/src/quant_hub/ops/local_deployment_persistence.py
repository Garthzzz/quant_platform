"""VM 本地单一 prior 部署的持久化基础设施。

本模块只提供固定根布局、可崩溃释放的全局锁、canonical JSON CAS、append-only
journal 与只规划不删除的 retention inventory。它不启动服务、不执行动态探针、不切换
writer，也不把 JSON 中的布尔值提升为部署资格。

生产构造没有 root、环境变量或配置入口，只能绑定
``D:\\quant\\quant_platform``。隔离测试必须显式调用 :meth:`for_test_only`；该工厂
不被 CLI 或产品配置导出。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import sqlite3
import stat
import threading
from typing import Callable, Iterable, Mapping, Sequence
import unicodedata
from urllib.parse import quote
import uuid

from . import local_release_identity as _identity


DEPLOYMENT_ATTEMPT_SCHEMA = "qrh-deployment-attempt/v4"
_VERIFIED_PHASE_CAS_OBSERVATION_SCHEMA = (
    "qrh-verified-phase-cas-observation/v1"
)
_VERIFIED_PHASE_CAS_OBSERVATION_SCOPE = "verified_phase_next_cas"
_BOOTSTRAP_POINTER_CAS_OBSERVATION_SCHEMA = (
    "qrh-bootstrap-pointer-cas-observation/v1"
)
_BOOTSTRAP_POINTER_CAS_OBSERVATION_SCOPE = (
    "bootstrap_absent_to_baseline_pointer_cas"
)
_FAILURE_STEADY_RECOVERY_AUTHORIZATION_SCHEMA = (
    "qrh-failure-steady-recovery-authorization/v1"
)
_FAILURE_STEADY_RECOVERY_AUTHORIZATION_SCOPE = (
    "failure_steady_recovery_authorization_only"
)
_FAILURE_SELECTION_AUTHORIZATION_SCHEMA = (
    "qrh-failure-selection-authorization/v1"
)
_FAILURE_SELECTION_AUTHORIZATION_SCOPE = "ordinary_failure_only"
_BOOTSTRAP_FAILURE_AUTHORIZATION_SCHEMA = (
    "qrh-bootstrap-failure-authorization/v1"
)
_BOOTSTRAP_FAILURE_AUTHORIZATION_SCOPE = (
    "bootstrap_absent_control_failure_only"
)
PRODUCTION_VM_ROOT_TEXT = r"D:\quant\quant_platform"

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_JOURNAL_NAME_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.r([0-9]{20})\.json$"
)
_EVIDENCE_DIRECTORY_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.evidence$"
)
_EVIDENCE_FILE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.json$"
)
_CONSTRUCTION_TOKEN = object()
_TEST_ONLY_TOKEN = object()
_LIVE_PRODUCTION_PERSISTENCE: dict[int, tuple[object, ...]] = {}
_ATTEMPT_WORKSPACE_TOKEN = object()
_STEADY_BOOT_WORKSPACE_TOKEN = object()
_LOCKED_STEADY_PAIR_STATIC_FACTS_TOKEN = object()
_LOCKED_STEADY_RELEASE_CLOSURES_TOKEN = object()
_PINNED_SQLITE_TOKEN = object()


def _aliases_exact_production_root(root: Path) -> bool:
    """Recognize lexical, resolved and same-file aliases without writing."""

    production = Path(PRODUCTION_VM_ROOT_TEXT)
    lexical = PureWindowsPath(os.path.normpath(str(root)))
    if lexical == PureWindowsPath(PRODUCTION_VM_ROOT_TEXT):
        return True
    try:
        resolved = root.resolve(strict=False)
    except OSError:
        resolved = root.absolute()
    if PureWindowsPath(os.path.normpath(str(resolved))) == PureWindowsPath(
        PRODUCTION_VM_ROOT_TEXT
    ):
        return True
    try:
        return root.exists() and production.exists() and os.path.samefile(
            root, production
        )
    except OSError:
        return False
_LOCKED_NEW_FILE_TOKEN = object()
_WORKSPACE_RESOURCE_CLOSE_TOKEN = object()
_LOCKED_STATE_SQLITE_SOURCE_TOKEN = object()
_LOCKED_STATE_SQLITE_VIEW_TOKEN = object()
_LOCKED_EXACT_RELEASE_CLOSURES_TOKEN = object()
_LOCKED_EXACT_TRANSIENT_START_AUTHORIZATION_TOKEN = object()
_LOCKED_VERIFIED_PHASE_CAS_AUTHORIZATION_TOKEN = object()
_LOCKED_EXACT_SCM_PROCESS_OBSERVATION_INPUT_TOKEN = object()
_LOCKED_WINDOWS_SCM_PROCESS_HANDLE_TRACKING_TOKEN = object()
_LOCKED_WINDOWS_STEADY_SCM_PROCESS_HANDLE_TRACKING_TOKEN = object()
_LOCKED_WINDOWS_WRITER_LEASE_HANDLE_TRACKING_TOKEN = object()
_LOCKED_WINDOWS_STEADY_WRITER_LEASE_HANDLE_TRACKING_TOKEN = object()
_LOCKED_MUTABLE_CANARY_SQLITE_SET_TOKEN = object()
_LOCKED_BOOTSTRAP_COMMENT_SCHEMA_EXPAND_AUTHORIZATION_TOKEN = object()

_BOOTSTRAP_COMMENT_SCHEMA_EXPAND_AUTHORIZATION_SCOPE = (
    "bootstrap_comment_schema_expand_authorization_only"
)

_EXACT_TRANSIENT_START_AUTHORIZATION_SCHEMA = (
    "qrh-exact-transient-start-authorization/v1"
)
_EXACT_TRANSIENT_START_AUTHORIZATION_SCOPE = (
    "exact_transient_start_authorization_input_only"
)
_EXACT_SCM_START_PLAN_SCHEMA = "qrh-exact-scm-start-plan/v1"
_EXACT_SCM_START_PLAN_SCOPE = "exact_scm_start_plan_input_only"
_EXACT_SCM_PROCESS_OBSERVATION_INPUT_SCOPE = (
    "exact_scm_process_observation_input_only"
)
_WINDOWS_SCM_PROCESS_HANDLE_TRACKING_SCOPE = (
    "windows_scm_process_handle_tracking_only"
)
_WINDOWS_STEADY_SCM_PROCESS_HANDLE_TRACKING_SCOPE = (
    "windows_steady_scm_process_handle_tracking_only"
)
_WINDOWS_WRITER_LEASE_HANDLE_TRACKING_SCOPE = (
    "windows_writer_lease_handle_tracking_only"
)
_WINDOWS_STEADY_WRITER_LEASE_HANDLE_TRACKING_SCOPE = (
    "windows_steady_writer_lease_handle_tracking_only"
)
_MUTABLE_CANARY_SQLITE_SET_SCOPE = "mutable_canary_sqlite_open_instance_only"
_EXACT_SCM_SERVICE_NAME = "QuantResearchHub"
_EXACT_SCM_PYTHON_CLASS = (
    "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
)
_EXACT_SCM_HOST_EXECUTABLE = (
    r"D:\quant\quant_platform\tooling\python\pythonservice.exe"
)
_LEGACY_EXACT_SCM_HOST_EXECUTABLE = (
    r"D:\quant\quant_platform\tooling\python\Lib\site-packages\win32\pythonservice.exe"
)
_EXACT_SCM_CHILD_EXECUTABLE = r"D:\quant\quant_platform\tooling\python\python.exe"
_EXACT_SCM_CHILD_MODULE = "quant_hub.ops.local_exact_runtime_entry"
_EXACT_SCM_PYCACHE_PARENT = (
    r"D:\quant\quant_platform\tmp\service\pycache"
)

_EXACT_RELEASE_MIGRATIONS = (
    "migrations/research_workspace/0001_research_workspace.down.sql",
    "migrations/research_workspace/0001_research_workspace.up.sql",
    "migrations/research_workspace/0002_project_semantics.down.sql",
    "migrations/research_workspace/0002_project_semantics.up.sql",
    "migrations/research_workspace/0003_project_creation_command.down.sql",
    "migrations/research_workspace/0003_project_creation_command.up.sql",
)
_EXACT_RELEASE_RUNTIME_MIGRATIONS = tuple(
    f"runtime_contract/{path}" for path in _EXACT_RELEASE_MIGRATIONS
)
_EXACT_RELEASE_MIGRATION_LAYOUTS = (
    _EXACT_RELEASE_MIGRATIONS,
    _EXACT_RELEASE_RUNTIME_MIGRATIONS,
)

# kernel lock 尚未取得前，Windows directory-handle enter 也可能部分成功后失败。
# 这个进程内 reservation 只封闭该极短 pre-kernel 窗口；跨进程权威仍完全由下面
# 的 OS file lock 提供。reservation 随进程 crash 消失，不创建第二个持久权威。
_PROCESS_LOCK_REGISTRY_GUARD = threading.Lock()
_PROCESS_LOCK_REGISTRY: dict[str, "CrashReleasedFileLock"] = {}

_ATTEMPT_WORKSPACE_SCHEMA = "qrh-deployment-attempt-workspace/v1"
_ATTEMPT_WORKSPACE_PARENT = "deployment-attempts"
_ATTEMPT_WORKSPACE_BINDING = "workspace_binding.json"
_STEADY_BOOT_WORKSPACE_SCOPE = "steady_boot_workspace_only"
_STEADY_PAIR_STATIC_FACTS_SCOPE = (
    "steady_pair_static_facts_not_start_authorization"
)
_STEADY_RELEASE_CLOSURES_SCOPE = (
    "steady_active_prior_release_closures_not_start_authorization"
)
_STATE_SQLITE_DATABASES = {
    "comments": "comments.sqlite3",
    "research_workspace": "research_workspace.sqlite3",
}

_LAYOUT_DIRECTORIES = (
    "incoming",
    "releases",
    "control",
    "state",
    "audit",
    "locks",
    "tmp",
    "logs",
    "audit/deployment_attempts",
    "audit/receipts",
    "audit/events",
)
_ORDINARY_PHASES = (
    "intent_durable",
    "root_preflight_verified",
    "state_expand_applied",
    "prior_start_authorized",
    "prior_verified",
    "pointer_cas_committed",
    "candidate_start_authorized",
    "candidate_verified",
    "binding_cas_committed",
    "terminal_receipt_committed",
    "cleanup_authorized",
    "cleanup_planned",
    "cleanup_receipt_committed",
)
_BOOTSTRAP_PHASES = (
    "intent_durable",
    "root_preflight_verified",
    "state_expand_applied",
    "pointer_cas_committed",
    "candidate_start_authorized",
    "candidate_verified",
    "terminal_receipt_committed",
)
_JOURNAL_PHASES = tuple(dict.fromkeys((*_ORDINARY_PHASES, *_BOOTSTRAP_PHASES)))
_FAILURE_PHASE = "failure_receipt_committed"
_FAILURE_RECEIPT_OPERATION = {
    "activation": "activate_successor",
    "rollback": "rollback_to_prior",
    "bootstrap_first_pair": "bootstrap_first_pair",
}


class LocalDeploymentPersistenceError(RuntimeError):
    """本地部署持久化合同失败。"""


class UnsafeLocalPath(LocalDeploymentPersistenceError):
    """路径不是精确普通、非 reparse 的批准 D-root 路径。"""


class DeploymentLockBusy(LocalDeploymentPersistenceError):
    """另一进程或线程持有全局部署锁。"""


class CompareAndSwapConflict(LocalDeploymentPersistenceError):
    """CAS 观察到 expected/desired 之外的第三值。"""


class DeploymentJournalError(LocalDeploymentPersistenceError):
    """deployment attempt journal 不满足 closed/hash-chain 合同。"""


class RetentionPlanningError(LocalDeploymentPersistenceError):
    """release retention inventory 无法安全闭合。"""


class _LockAcquisitionEpoch:
    """Identity-only lease generation which cannot cross a serialization boundary."""

    __slots__ = ()

    def __reduce__(self) -> object:
        raise TypeError("lock acquisition epoch is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("lock acquisition epoch is process-local and non-serializable")


@dataclass(frozen=True, slots=True)
class CanonicalJsonRecord:
    value: Mapping[str, object]
    sha256: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class CompareAndSwapResult:
    outcome: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ReleaseInventoryEntry:
    release_id: str
    canonical_path: str
    manifest_sha256: str
    closure_sha256: str


@dataclass(frozen=True, slots=True)
class ReleaseCleanupTargetPlan:
    kind: str
    canonical_path: str
    release_id: str
    manifest_sha256: str
    closure_sha256: str


@dataclass(frozen=True, slots=True)
class IncomingCleanupTargetPlan:
    kind: str
    canonical_path: str
    payload_sha256: str
    closure_sha256: str


@dataclass(frozen=True, slots=True)
class PartialCleanupTargetPlan:
    kind: str
    canonical_path: str
    payload_sha256: str
    closure_sha256: str


@dataclass(frozen=True, slots=True)
class UnreferencedObjectCleanupTargetPlan:
    kind: str
    canonical_path: str
    object_sha256: str
    closure_sha256: str


CleanupTargetPlan = (
    ReleaseCleanupTargetPlan
    | IncomingCleanupTargetPlan
    | PartialCleanupTargetPlan
    | UnreferencedObjectCleanupTargetPlan
)


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    active: ReleaseInventoryEntry
    prior: ReleaseInventoryEntry | None
    transient: ReleaseInventoryEntry | None
    cleanup_targets: tuple[CleanupTargetPlan, ...]
    release_count: int
    active_attempt: str | None


def _safe_identifier(value: object, *, label: str) -> str:
    try:
        return _identifier(value, label=label)
    except DeploymentJournalError as error:
        raise UnsafeLocalPath(f"{label} 不是 Windows-safe 标识") from error


def _closed_relative_parts(value: object, *, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or _CONTROL_RE.search(value)
        or unicodedata.normalize("NFKC", value) != value
        or "\\" in value
    ):
        raise UnsafeLocalPath(f"{label} 不是 closed relative path")
    candidate = PurePosixPath(value)
    parts = candidate.parts
    if (
        candidate.is_absolute()
        or not parts
        or len(parts) > 16
        or any(part in {"", ".", ".."} for part in parts)
        or candidate.as_posix() != value
    ):
        raise UnsafeLocalPath(f"{label} 不是 closed relative path")
    return tuple(
        _safe_identifier(part, label=f"{label} component") for part in parts
    )


def _identifier(value: object, *, label: str) -> str:
    windows_stem = value.split(".", 1)[0].casefold() if isinstance(value, str) else ""
    if (
        not isinstance(value, str)
        or _IDENTIFIER_RE.fullmatch(value) is None
        or ".." in value
        or value.endswith((".", " "))
        or windows_stem in _WINDOWS_DEVICE_NAMES
    ):
        raise DeploymentJournalError(f"{label} 不是稳定标识")
    return value


def _sha256(value: object, *, label: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if (
        not isinstance(value, str)
        or _SHA256_RE.fullmatch(value) is None
        or set(value) == {"0"}
    ):
        raise DeploymentJournalError(f"{label} 不是小写 SHA-256")
    return value


def _timestamp(value: object, *, label: str) -> datetime:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 64
        or _CONTROL_RE.search(value)
    ):
        raise DeploymentJournalError(f"{label} 不是合法时间戳")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DeploymentJournalError(f"{label} 不是 ISO-8601 时间戳") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DeploymentJournalError(f"{label} 缺少时区")
    return parsed


def _object(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise DeploymentJournalError(f"{label} 必须是 JSON object")
    return value


def _closed(
    value: object, fields: Iterable[str], *, label: str
) -> Mapping[str, object]:
    document = _object(value, label=label)
    if set(document) != set(fields):
        raise DeploymentJournalError(f"{label} schema 未闭合")
    return document


def _json_clone(value: object, *, label: str) -> Mapping[str, object]:
    try:
        cloned = json.loads(_identity.canonical_bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeploymentJournalError(f"{label} 不是 canonical JSON") from error
    if not isinstance(cloned, dict):
        raise DeploymentJournalError(f"{label} 必须是 JSON object")
    return cloned


def _validate_attempt_evidence(value: object) -> Mapping[str, object]:
    return _object(value, label="attempt evidence")


def _validate_failure_steady_recovery_authorization(
    value: object,
) -> Mapping[str, object]:
    authorization = _closed(
        value,
        {
            "schema_version",
            "scope",
            "attempt_id",
            "nonce",
            "operation",
            "failed_phase",
            "journal_sha256",
            "original_pair",
            "candidate",
            "state_identity_sha256",
            "active_pointer_raw_sha256",
            "local_prior_binding_raw_sha256",
            "production_state_order_sha256",
            "authorization_sha256",
        },
        label="failure steady recovery authorization",
    )
    if (
        authorization["schema_version"]
        != _FAILURE_STEADY_RECOVERY_AUTHORIZATION_SCHEMA
        or authorization["scope"]
        != _FAILURE_STEADY_RECOVERY_AUTHORIZATION_SCOPE
    ):
        raise DeploymentJournalError(
            "failure steady recovery authorization schema/scope 不符"
        )
    _identifier(authorization["attempt_id"], label="failure recovery attempt")
    _identifier(authorization["nonce"], label="failure recovery nonce")
    if authorization["operation"] not in {"activation", "rollback"}:
        raise DeploymentJournalError("failure recovery operation 无效")
    _identifier(
        authorization["failed_phase"], label="failure recovery failed phase"
    )
    original_pair = _pair(
        authorization["original_pair"],
        label="failure recovery original pair",
        allow_missing_active=False,
        allow_missing_prior=True,
    )
    candidate = _release_ref(
        authorization["candidate"], label="failure recovery candidate"
    )
    if candidate == original_pair["active"] or (
        original_pair["prior"] is not None
        and candidate == original_pair["prior"]
    ):
        raise DeploymentJournalError(
            "failure recovery candidate 必须区别于 original pair"
        )
    for field in (
        "journal_sha256",
        "state_identity_sha256",
        "active_pointer_raw_sha256",
        "local_prior_binding_raw_sha256",
        "production_state_order_sha256",
        "authorization_sha256",
    ):
        _sha256(authorization[field], label=f"failure recovery {field}")
    unsigned = dict(authorization)
    observed_hash = unsigned.pop("authorization_sha256")
    if _identity.identity_sha256(unsigned) != observed_hash:
        raise DeploymentJournalError(
            "failure steady recovery authorization hash 不闭合"
        )
    return authorization


def _validate_bootstrap_failure_authorization(
    value: object,
) -> Mapping[str, object]:
    authorization = _closed(
        value,
        {
            "schema_version",
            "scope",
            "attempt_id",
            "nonce",
            "operation",
            "failed_phase",
            "journal_sha256",
            "candidate",
            "state_identity_sha256",
            "active_pointer_raw_sha256",
            "local_prior_binding_raw_sha256",
            "production_state_order_sha256",
            "authorization_sha256",
        },
        label="bootstrap failure authorization",
    )
    if (
        authorization["schema_version"]
        != _BOOTSTRAP_FAILURE_AUTHORIZATION_SCHEMA
        or authorization["scope"] != _BOOTSTRAP_FAILURE_AUTHORIZATION_SCOPE
        or authorization["operation"] != "bootstrap_first_pair"
    ):
        raise DeploymentJournalError(
            "bootstrap failure authorization schema/scope differs"
        )
    _identifier(authorization["attempt_id"], label="bootstrap failure attempt")
    _identifier(authorization["nonce"], label="bootstrap failure nonce")
    _identifier(
        authorization["failed_phase"], label="bootstrap failure phase"
    )
    _release_ref(
        authorization["candidate"], label="bootstrap failure candidate"
    )
    for field in (
        "journal_sha256",
        "state_identity_sha256",
        "active_pointer_raw_sha256",
        "local_prior_binding_raw_sha256",
        "production_state_order_sha256",
        "authorization_sha256",
    ):
        _sha256(authorization[field], label=f"bootstrap failure {field}")
    unsigned = dict(authorization)
    observed_hash = unsigned.pop("authorization_sha256")
    if _identity.identity_sha256(unsigned) != observed_hash:
        raise DeploymentJournalError(
            "bootstrap failure authorization hash does not close"
        )
    absent_sha256 = hashlib.sha256(b"absent").hexdigest()
    if (
        authorization["active_pointer_raw_sha256"] != absent_sha256
        or authorization["local_prior_binding_raw_sha256"] != absent_sha256
    ):
        raise DeploymentJournalError(
            "bootstrap failure authorization did not bind absent controls"
        )
    return authorization


def _validate_failure_selection_authorization(
    value: object,
) -> Mapping[str, object]:
    authorization = _closed(
        value,
        {
            "schema_version",
            "scope",
            "attempt_id",
            "nonce",
            "operation",
            "failed_phase",
            "journal_sha256",
            "original_pair",
            "target_pair",
            "candidate",
            "state_identity_sha256",
            "allowed_active_control_sha256",
            "allowed_binding_control_sha256",
            "authorization_sha256",
        },
        label="failure selection authorization",
    )
    if (
        authorization["schema_version"]
        != _FAILURE_SELECTION_AUTHORIZATION_SCHEMA
        or authorization["scope"] != _FAILURE_SELECTION_AUTHORIZATION_SCOPE
        or authorization["operation"] not in {"activation", "rollback"}
    ):
        raise DeploymentJournalError(
            "failure selection authorization schema/scope differs"
        )
    _identifier(authorization["attempt_id"], label="failure selection attempt")
    _identifier(authorization["nonce"], label="failure selection nonce")
    _identifier(authorization["failed_phase"], label="failure selection phase")
    _pair(
        authorization["original_pair"],
        label="failure selection original pair",
        allow_missing_active=False,
        allow_missing_prior=True,
    )
    _pair(
        authorization["target_pair"],
        label="failure selection target pair",
        allow_missing_active=False,
        allow_missing_prior=True,
    )
    _release_ref(authorization["candidate"], label="failure selection candidate")
    _sha256(authorization["journal_sha256"], label="failure selection journal")
    _sha256(
        authorization["state_identity_sha256"],
        label="failure selection state identity",
    )
    for field in (
        "allowed_active_control_sha256",
        "allowed_binding_control_sha256",
    ):
        values = authorization[field]
        if (
            not isinstance(values, list)
            or not values
            or len(values) > 2
            or values != sorted(set(values))
        ):
            raise DeploymentJournalError(
                f"failure selection {field} is not a closed hash set"
            )
        for item in values:
            _sha256(item, label=f"failure selection {field}")
    observed_hash = authorization["authorization_sha256"]
    _sha256(observed_hash, label="failure selection authorization")
    unsigned = dict(authorization)
    unsigned.pop("authorization_sha256")
    if _identity.identity_sha256(unsigned) != observed_hash:
        raise DeploymentJournalError(
            "failure selection authorization hash does not close"
        )
    return authorization


def _validate_verified_phase_cas_observation(
    value: object,
) -> Mapping[str, object]:
    observation = _closed(
        value,
        {
            "schema_version",
            "scope",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "verified_journal_sha256",
            "qualification_sha256",
            "action",
            "target",
            "expected",
            "desired",
            "result",
            "observation_sha256",
        },
        label="verified-phase CAS observation",
    )
    if (
        observation["schema_version"]
        != _VERIFIED_PHASE_CAS_OBSERVATION_SCHEMA
        or observation["scope"] != _VERIFIED_PHASE_CAS_OBSERVATION_SCOPE
    ):
        raise DeploymentJournalError("verified-phase CAS observation schema/scope 不符")
    _identifier(observation["attempt_id"], label="CAS observation attempt")
    _identifier(observation["nonce"], label="CAS observation nonce")
    if observation["operation"] not in {"activation", "rollback"}:
        raise DeploymentJournalError("verified-phase CAS observation operation 无效")
    role = observation["role"]
    action = observation["action"]
    target = observation["target"]
    expected = observation["expected"]
    desired = observation["desired"]
    if role == "prior":
        if action != "active_pointer_cas" or target != "active_release":
            raise DeploymentJournalError("prior CAS observation action/target 不符")
        expected_value = _identity.validate_active_release(expected)
        desired_value = _identity.validate_active_release(desired)
    elif role == "candidate":
        if action != "local_prior_binding_cas" or target != "local_prior_binding":
            raise DeploymentJournalError("candidate CAS observation action/target 不符")
        expected_value = (
            None
            if expected is None
            else _identity.validate_local_prior_binding(expected)
        )
        desired_value = _identity.validate_local_prior_binding(desired)
    else:
        raise DeploymentJournalError("verified-phase CAS observation role 无效")
    _sha256(
        observation["verified_journal_sha256"],
        label="CAS observation verified journal",
    )
    _sha256(
        observation["qualification_sha256"],
        label="CAS observation qualification",
    )
    result = _closed(
        observation["result"],
        {"status", "expected_sha256", "desired_sha256"},
        label="verified-phase CAS observation result",
    )
    expected_sha256 = (
        None
        if expected_value is None
        else hashlib.sha256(_identity.canonical_bytes(expected_value)).hexdigest()
    )
    desired_sha256 = hashlib.sha256(
        _identity.canonical_bytes(desired_value)
    ).hexdigest()
    if (
        result["status"] != "desired_durable"
        or result["expected_sha256"] != expected_sha256
        or result["desired_sha256"] != desired_sha256
    ):
        raise DeploymentJournalError("verified-phase CAS observation result 不闭合")
    _sha256(
        observation["observation_sha256"],
        label="CAS observation self hash",
    )
    unsigned = dict(observation)
    unsigned.pop("observation_sha256", None)
    if observation["observation_sha256"] != _identity.identity_sha256(unsigned):
        raise DeploymentJournalError("verified-phase CAS observation self hash 不符")
    cloned = json.loads(_identity.canonical_bytes(observation).decode("utf-8"))
    if type(cloned) is not dict:
        raise DeploymentJournalError("verified-phase CAS observation clone 类型漂移")
    return cloned


def _validate_attempt_workspace_binding(value: object) -> Mapping[str, object]:
    document = _closed(
        value,
        {"schema_version", "attempt_id", "nonce"},
        label="attempt workspace binding",
    )
    if document["schema_version"] != _ATTEMPT_WORKSPACE_SCHEMA:
        raise DeploymentJournalError("attempt workspace binding schema 错误")
    _identifier(document["attempt_id"], label="workspace binding attempt")
    _identifier(document["nonce"], label="workspace binding nonce")
    _identifier(
        f"{document['attempt_id']}-{document['nonce']}",
        label="workspace binding component",
    )
    return document


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _descriptor_no_longer_exact(
    descriptor: int,
    expected: os.stat_result | None,
) -> bool:
    """只读证明 fd 已无效或已不再代表原资源。"""

    try:
        observed = os.fstat(descriptor)
    except OSError as error:
        if error.errno == errno.EBADF:
            return True
        raise LocalDeploymentPersistenceError(
            "无法证明 descriptor close 后身份"
        ) from error
    if expected is None:
        # 句柄已经登记但首次 fstat 尚未成功时，只能以 EBADF 证明它已关闭；
        # 仍有效的未知 descriptor 必须保留，不能猜测身份后遗失 tracking。
        return False
    return not _same_file_identity(observed, expected)


class _BoundDirectory:
    """绑定真实目录身份，并在 Windows 上禁止目录链被 rename/delete。

    Windows 没有可供 ``os.replace`` 使用的 ``dir_fd``。因此产品路径在副作用期间从
    卷根到目标父目录逐级持有不共享 ``FILE_SHARE_DELETE`` 的目录 handle；攻击者无法
    在最后一次 preflight 后替换任一组件。POSIX 仅为 test-only，使用真实 dir-fd 相对
    操作，避免重新解析父路径。
    """

    def __init__(
        self,
        safe_root: "_SafeRoot",
        path: Path,
        *,
        protect_rename: bool = True,
        allow_self_rename: bool = False,
    ):
        if protect_rename and allow_self_rename:
            raise UnsafeLocalPath(
                "bound directory cannot both block and perform self rename"
            )
        self._safe_root = safe_root
        self.path = path
        self._protect_rename = protect_rename
        self._allow_self_rename = allow_self_rename
        self._windows_handles: list[int] = []
        self._windows_handle_identities: dict[
            int, tuple[str, int | None, int | None, int | None]
        ] = {}
        self._descriptor: int | None = None
        self._descriptor_identity: os.stat_result | None = None

    @staticmethod
    def _windows_final_path(handle: int) -> str:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetFinalPathNameByHandleW.argtypes = (
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        size = kernel32.GetFinalPathNameByHandleW(handle, None, 0, 0)
        if size == 0:
            raise UnsafeLocalPath("无法读取 Windows directory handle final path")
        buffer = ctypes.create_unicode_buffer(size + 1)
        written = kernel32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            raise UnsafeLocalPath("Windows directory handle final path 漂移")
        rendered = buffer.value
        if rendered.startswith("\\\\?\\UNC\\"):
            rendered = "\\\\" + rendered[8:]
        elif rendered.startswith("\\\\?\\"):
            rendered = rendered[4:]
        return rendered.rstrip("\\") if len(rendered) > 3 else rendered

    @staticmethod
    def _open_windows_directory(
        path: Path,
        *,
        protect_rename: bool,
        allow_self_rename: bool = False,
    ) -> int:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x00000080
            | (0x00010000 if allow_self_rename else 0),
            # FILE_READ_ATTRIBUTES；保护方通过不共享 FILE_SHARE_DELETE
            # 阻断 rename/delete，无需同时申请 DELETE access。同时申请
            # DELETE 会使两个都不共享 delete 的正当保护者互相冲突。
            0x00000001 | 0x00000002 | (0 if protect_rename else 0x00000004),
            # 被保护目录 intentionally no SHARE_DELETE；只读祖先允许复用 owner 的 root guard。
            None,
            3,  # OPEN_EXISTING
            0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            raise UnsafeLocalPath(
                f"无法绑定 Windows directory handle {path}: {ctypes.get_last_error()}"
            )
        attributes = os.lstat(path)
        if (
            not stat.S_ISDIR(attributes.st_mode)
            or stat.S_ISLNK(attributes.st_mode)
            or _is_reparse(attributes)
        ):
            kernel32.CloseHandle(handle)
            raise UnsafeLocalPath("Windows bound directory 是 reparse/non-directory")
        if _BoundDirectory._windows_final_path(handle) != str(path):
            kernel32.CloseHandle(handle)
            raise UnsafeLocalPath("Windows bound directory 不是 exact final path")
        return int(handle)

    @staticmethod
    def _close_windows_handle(handle: int) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        if not kernel32.CloseHandle(handle):
            error = ctypes.get_last_error()
            raise OSError(error, f"CloseHandle failed for {handle}")

    @staticmethod
    def _windows_kernel_identity(handle: int) -> tuple[int, int, int]:
        import ctypes
        from ctypes import wintypes

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = (
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        )
        kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            handle, ctypes.byref(information)
        ):
            error = ctypes.get_last_error()
            raise OSError(error, f"GetFileInformationByHandle failed for {handle}")
        return (
            int(information.dwVolumeSerialNumber),
            int(information.nFileIndexHigh),
            int(information.nFileIndexLow),
        )

    @staticmethod
    def _windows_handle_no_longer_exact(
        handle: int,
        expected_identity: tuple[
            str, int | None, int | None, int | None
        ],
    ) -> bool:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetHandleInformation.argtypes = (
            wintypes.HANDLE,
            wintypes.LPDWORD,
        )
        kernel32.GetHandleInformation.restype = wintypes.BOOL
        flags = wintypes.DWORD()
        if not kernel32.GetHandleInformation(handle, ctypes.byref(flags)):
            error = ctypes.get_last_error()
            if error == 6:  # ERROR_INVALID_HANDLE
                return True
            raise UnsafeLocalPath(
                f"无法证明 Windows handle close 后身份: {error}"
            )
        expected_path, expected_volume, expected_high, expected_low = (
            expected_identity
        )
        try:
            observed_kernel_identity = _BoundDirectory._windows_kernel_identity(
                handle
            )
            observed_path = _BoundDirectory._windows_final_path(handle)
        except OSError as error:
            if getattr(error, "winerror", None) == 6 or error.errno == 6:
                return True
            raise UnsafeLocalPath(
                "无法证明 Windows handle close 后 exact identity"
            ) from error
        return (
            observed_path,
            *observed_kernel_identity,
        ) != expected_identity if expected_volume is not None else (
            observed_path != expected_path
        )

    def __enter__(self) -> "_BoundDirectory":
        self._safe_root.preflight(
            self.path, expected_kind="directory", allow_absent=False
        )
        if os.name == "nt":
            # 逐级绑定卷根、root 的父组件、root 以及目标父目录；任何祖先 rename
            # 都会因缺少 FILE_SHARE_DELETE 而在第一次越界写前失败。
            chain: list[Path] = []
            current = self.path
            while True:
                chain.append(current)
                if current.parent == current:
                    break
                current = current.parent
            try:
                for component in reversed(chain):
                    # 只给本次操作的真实父目录申请 DELETE access。其余 root 内祖先
                    # 已由全局锁持有的 root/locks 目录链约束；重复申请 DELETE 会与
                    # 自己“不共享 delete”的句柄冲突。
                    protect_rename = self._protect_rename and component == self.path
                    allow_self_rename = (
                        self._allow_self_rename and component == self.path
                    )
                    if allow_self_rename:
                        handle = self._open_windows_directory(
                            component,
                            protect_rename=protect_rename,
                            allow_self_rename=True,
                        )
                    else:
                        # Preserve the long-standing two-argument seam used by
                        # failure-injection tests and ordinary protected binds.
                        handle = self._open_windows_directory(
                            component,
                            protect_rename=protect_rename,
                        )
                    self._windows_handle_identities[handle] = (
                        str(component), None, None, None
                    )
                    self._windows_handles.append(handle)
                    self._windows_handle_identities[handle] = (
                        str(component),
                        *self._windows_kernel_identity(handle),
                    )
            except Exception:
                self.__exit__(None, None, None)
                raise
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            self._descriptor = os.open(self.path, flags)
            opened = os.fstat(self._descriptor)
            self._descriptor_identity = opened
            observed = self._safe_root.preflight(
                self.path, expected_kind="directory", allow_absent=False
            )
            if observed is None or not _same_file_identity(opened, observed):
                self.__exit__(None, None, None)
                raise UnsafeLocalPath("POSIX directory fd 身份漂移")
        return self

    @staticmethod
    def _child_name(name: str) -> str:
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise UnsafeLocalPath("relative child name 不安全")
        return name

    def open_file(self, name: str, flags: int, mode: int = 0o600) -> int:
        name = self._child_name(name)
        if os.name == "nt":
            return os.open(self.path / name, flags, mode)
        if self._descriptor is None:
            raise UnsafeLocalPath("POSIX directory fd 未绑定")
        return os.open(name, flags, mode, dir_fd=self._descriptor)

    def mkdir(self, name: str, mode: int = 0o700) -> None:
        name = self._child_name(name)
        if os.name == "nt":
            os.mkdir(self.path / name, mode)
            return
        if self._descriptor is None:
            raise UnsafeLocalPath("POSIX directory fd 未绑定")
        os.mkdir(name, mode, dir_fd=self._descriptor)

    def unlink(self, name: str) -> None:
        name = self._child_name(name)
        if os.name == "nt":
            os.unlink(self.path / name)
            return
        if self._descriptor is None:
            raise UnsafeLocalPath("POSIX directory fd 未绑定")
        os.unlink(name, dir_fd=self._descriptor)

    def rmdir(self, name: str) -> None:
        name = self._child_name(name)
        if os.name == "nt":
            os.rmdir(self.path / name)
            return
        if self._descriptor is None:
            raise UnsafeLocalPath("POSIX directory fd 未绑定")
        os.rmdir(name, dir_fd=self._descriptor)

    def replace_from(
        self,
        source: "_BoundDirectory",
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        source_name = self._child_name(source_name)
        destination_name = self._child_name(destination_name)
        if os.name == "nt":
            os.replace(
                source.path / source_name,
                self.path / destination_name,
            )
            return
        if self._descriptor is None or source._descriptor is None:
            raise UnsafeLocalPath("POSIX replace 缺 directory fd")
        os.replace(
            source_name,
            destination_name,
            src_dir_fd=source._descriptor,
            dst_dir_fd=self._descriptor,
        )

    def replace_open_windows_handle(
        self,
        handle: int,
        *,
        destination_name: str,
        replace_existing: bool,
    ) -> None:
        """Rename one already-pinned Windows object into this directory.

        The source is selected by its live kernel handle, never by reopening a
        path.  The destination parent is the exact directory handle held by
        this object.  This is the production publication seam for immutable
        files, including writer-handoff SQLite state members.
        """

        destination_name = self._child_name(destination_name)
        if os.name != "nt":
            raise UnsafeLocalPath(
                "open-handle publication is available only on production Windows"
            )
        if type(handle) is not int or handle <= 0 or not self._windows_handles:
            raise UnsafeLocalPath("open-handle publication lacks exact handles")

        import ctypes
        from ctypes import wintypes

        parent_handle = self._windows_handles[-1]
        if self._windows_final_path(parent_handle) != str(self.path):
            raise UnsafeLocalPath("publication destination parent identity drifted")

        class _FileRenameInfo(ctypes.Structure):
            _fields_ = (
                ("Flags", wintypes.DWORD),
                ("RootDirectory", wintypes.HANDLE),
                ("FileNameLength", wintypes.DWORD),
                ("FileName", wintypes.WCHAR * 1),
            )

        # SetFileInformationByHandle selects the source by ``handle``.  Windows
        # user mode rejects a directory HANDLE in ``RootDirectory`` for this
        # information class on supported production builds, so the destination
        # is rendered as the absolute child of our still-live no-rename parent
        # handle.  No source path is reopened and no destination ancestor can
        # be exchanged while the syscall runs.
        destination_path = self.path / destination_name
        encoded_name = str(destination_path).encode("utf-16-le")
        filename_offset = _FileRenameInfo.FileName.offset
        # Keep the trailing UTF-16 NUL even though FileNameLength excludes it;
        # Windows validates the variable-sized FILE_RENAME_INFO buffer itself.
        buffer = ctypes.create_string_buffer(
            filename_offset + len(encoded_name) + ctypes.sizeof(wintypes.WCHAR)
        )
        information = ctypes.cast(
            buffer, ctypes.POINTER(_FileRenameInfo)
        ).contents
        information.Flags = 0x00000002 | (
            0x00000001 if replace_existing else 0
        )  # FILE_RENAME_FLAG_POSIX_SEMANTICS | optional REPLACE_IF_EXISTS
        information.RootDirectory = None
        information.FileNameLength = len(encoded_name)
        ctypes.memmove(
            ctypes.addressof(buffer) + filename_offset,
            encoded_name,
            len(encoded_name),
        )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
        if not kernel32.SetFileInformationByHandle(
            wintypes.HANDLE(handle),
            22,  # FileRenameInfoEx (Windows 10 / Server 2016+)
            ctypes.byref(buffer),
            len(buffer),
        ):
            raise UnsafeLocalPath(
                "open-handle publication failed: "
                f"Windows error {ctypes.get_last_error()}"
            )

    def windows_leaf_identity(self) -> tuple[int, int, int]:
        """Return the live Windows kernel identity of this exact directory."""

        if os.name != "nt" or not self._windows_handles:
            raise UnsafeLocalPath("bound directory lacks a live Windows leaf handle")
        handle = self._windows_handles[-1]
        if self._windows_final_path(handle) != str(self.path):
            raise UnsafeLocalPath("bound directory leaf final path drifted")
        return self._windows_kernel_identity(handle)

    def windows_leaf_handle(self) -> int:
        """Return the live exact Windows leaf handle after final-path proof."""

        if os.name != "nt" or not self._windows_handles:
            raise UnsafeLocalPath("bound directory lacks a live Windows leaf handle")
        handle = self._windows_handles[-1]
        if self._windows_final_path(handle) != str(self.path):
            raise UnsafeLocalPath("bound directory leaf final path drifted")
        return handle

    def enable_self_rename(self) -> None:
        """Acquire DELETE access and prove it is the already-bound leaf."""

        if os.name != "nt" or not self._windows_handles:
            raise UnsafeLocalPath("self-rename upgrade requires a Windows leaf")
        if self._protect_rename:
            raise UnsafeLocalPath("protected directory cannot enable self rename")
        source_handle = self._windows_handles[-1]
        source_identity = self._windows_kernel_identity(source_handle)
        # Windows cannot add DELETE access to the existing directory handle.
        # The new handle is therefore opened by name only after the no-rename
        # construction handles retire, then compared to the still-live
        # share-delete handle's kernel identity before it gains authority.
        # It deliberately does *not* share DELETE. Windows permits a rename
        # performed through this same handle, while every competing path-based
        # rename is denied continuously before and after that syscall.
        handle = self._open_windows_directory(
            self.path,
            protect_rename=True,
        )
        try:
            if (
                self._windows_kernel_identity(handle) != source_identity
                or self._windows_final_path(handle) != str(self.path)
            ):
                raise UnsafeLocalPath("self-rename upgrade identity drifted")
            self._windows_handles.append(handle)
            self._windows_handle_identities[handle] = (
                str(self.path),
                *source_identity,
            )
            self._allow_self_rename = True
        except BaseException:
            self._close_windows_handle(handle)
            raise

    def rename_self_to(
        self,
        destination_parent: "_BoundDirectory",
        *,
        destination_name: str,
    ) -> None:
        """Publish this exact bound directory by its already-open handle."""

        destination_name = self._child_name(destination_name)
        old_path = self.path
        new_path = destination_parent.path / destination_name
        if os.name != "nt":
            if old_path.parent != destination_parent.path:
                raise UnsafeLocalPath("POSIX bound directory rename crossed parents")
            if self._descriptor is None or destination_parent._descriptor is None:
                raise UnsafeLocalPath("POSIX bound directory rename lacks dir fd")
            os.rename(
                old_path.name,
                destination_name,
                src_dir_fd=destination_parent._descriptor,
                dst_dir_fd=destination_parent._descriptor,
            )
            self.path = new_path
            return
        if not self._allow_self_rename or not self._windows_handles:
            raise UnsafeLocalPath("bound directory lacks self-rename authority")
        destination_parent.replace_open_windows_handle(
            self._windows_handles[-1],
            destination_name=destination_name,
            replace_existing=False,
        )
        self.rebase_after_ancestor_rename(
            old_ancestor=old_path,
            new_ancestor=new_path,
        )

    def rebase_after_ancestor_rename(
        self,
        *,
        old_ancestor: Path,
        new_ancestor: Path,
    ) -> None:
        """Record and verify tracked paths after an ancestor handle rename."""

        self.record_ancestor_rename(
            old_ancestor=old_ancestor,
            new_ancestor=new_ancestor,
        )
        self.verify_windows_final_paths()

    def record_ancestor_rename(
        self,
        *,
        old_ancestor: Path,
        new_ancestor: Path,
    ) -> None:
        """Record an already-completed rename before any fallible proof."""

        try:
            relative = self.path.relative_to(old_ancestor)
        except ValueError as error:
            raise UnsafeLocalPath("bound directory is outside renamed ancestor") from error
        self.path = new_ancestor / relative
        if os.name != "nt":
            return
        for handle, identity in tuple(self._windows_handle_identities.items()):
            expected = Path(identity[0])
            try:
                suffix = expected.relative_to(old_ancestor)
            except ValueError:
                continue
            updated = new_ancestor / suffix
            self._windows_handle_identities[handle] = (
                str(updated), identity[1], identity[2], identity[3]
            )

    def transfer_windows_binding(
        self,
        *,
        protect_rename: bool,
    ) -> "_BoundDirectory":
        """Transfer every live Windows handle without closing or reopening it."""

        if os.name != "nt" or not self._windows_handles:
            raise UnsafeLocalPath("Windows binding transfer lacks live handles")
        transferred = _BoundDirectory(
            self._safe_root,
            self.path,
            protect_rename=protect_rename,
        )
        transferred._windows_handles = self._windows_handles
        transferred._windows_handle_identities = self._windows_handle_identities
        self._windows_handles = []
        self._windows_handle_identities = {}
        self._allow_self_rename = False
        return transferred

    def verify_windows_final_paths(self) -> None:
        """Prove every live Windows handle still has its recorded final path."""

        if os.name != "nt":
            return
        for handle, identity in tuple(self._windows_handle_identities.items()):
            updated = Path(identity[0])
            if self._windows_final_path(handle) != str(updated):
                raise UnsafeLocalPath(
                    "bound directory descendant path differs after ancestor rename"
                )

    def retire_self_rename_authority(self) -> None:
        """Close only the DELETE/share-delete upgrade, retaining the leaf pin."""

        if os.name != "nt" or not self._allow_self_rename:
            raise UnsafeLocalPath("bound directory self-rename authority is absent")
        if not self._windows_handles:
            raise UnsafeLocalPath("bound directory self-rename handle is absent")
        handle = self._windows_handles.pop()
        self._windows_handle_identities.pop(handle, None)
        self._close_windows_handle(handle)
        self._allow_self_rename = False

    @staticmethod
    def delete_open_windows_handle(handle: int) -> None:
        """Mark the exact DELETE-authorized Windows object for POSIX deletion."""

        if os.name != "nt" or type(handle) is not int or handle <= 0:
            raise UnsafeLocalPath("exact handle deletion requires Windows authority")
        import ctypes
        from ctypes import wintypes

        class _FileDispositionInfoEx(ctypes.Structure):
            _fields_ = (("Flags", wintypes.DWORD),)

        information = _FileDispositionInfoEx()
        information.Flags = 0x00000001 | 0x00000002
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
        if not kernel32.SetFileInformationByHandle(
            wintypes.HANDLE(handle),
            21,  # FileDispositionInfoEx
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise UnsafeLocalPath(
                "open-handle deletion failed: "
                f"Windows error {ctypes.get_last_error()}"
            )

    def flush(self) -> None:
        if os.name != "nt" and self._descriptor is not None:
            os.fsync(self._descriptor)

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        close_error: BaseException | None = None
        if self._descriptor is not None:
            descriptor = self._descriptor
            identity = self._descriptor_identity
            if identity is None:
                raise UnsafeLocalPath("POSIX bound directory 缺 descriptor identity")
            try:
                os.close(descriptor)
            except OSError as error:
                try:
                    no_longer_exact = _descriptor_no_longer_exact(
                        descriptor, identity
                    )
                except BaseException as proof_error:
                    no_longer_exact = False
                    close_error = proof_error
                if no_longer_exact:
                    self._descriptor = None
                    self._descriptor_identity = None
                elif close_error is None:
                    close_error = error
            else:
                self._descriptor = None
                self._descriptor_identity = None
        for index in range(len(self._windows_handles) - 1, -1, -1):
            handle = self._windows_handles[index]
            expected_identity = self._windows_handle_identities[handle]
            try:
                self._close_windows_handle(handle)
            except BaseException as error:
                try:
                    no_longer_exact = self._windows_handle_no_longer_exact(
                        handle, expected_identity
                    )
                except BaseException as proof_error:
                    no_longer_exact = False
                    if close_error is None:
                        close_error = proof_error
                if not no_longer_exact:
                    if close_error is None:
                        close_error = error
                    continue
            del self._windows_handles[index]
            self._windows_handle_identities.pop(handle, None)
        if close_error is not None:
            raise LocalDeploymentPersistenceError(
                "bound directory 关闭未机械闭合"
            ) from close_error

    def _fully_closed(self) -> bool:
        return (
            self._descriptor is None
            and self._descriptor_identity is None
            and not self._windows_handles
            and not self._windows_handle_identities
        )


class _SafeRoot:
    """在任何模块写入前验证 exact root、组件身份与大小写。"""

    def __init__(self, root: Path, *, allow_posix_test_only: bool):
        if not isinstance(root, Path) or not root.is_absolute():
            raise UnsafeLocalPath("部署根必须是显式绝对 Path")
        if os.name != "nt" and not allow_posix_test_only:
            raise UnsafeLocalPath("POSIX 只允许显式 test-only adapter")
        if str(root).startswith(("\\\\", "//")):
            raise UnsafeLocalPath("UNC 根不属于本地 D-root 合同")
        if ".." in root.parts:
            raise UnsafeLocalPath("部署根含路径逃逸")
        self.root = root
        self._verify_exact_existing_root()

    def _verify_exact_existing_root(self) -> None:
        try:
            resolved = self.root.resolve(strict=True)
        except OSError as error:
            raise UnsafeLocalPath("部署根必须在写入前已存在") from error
        if str(resolved) != str(self.root):
            raise UnsafeLocalPath("部署根不是 exact canonical path")
        for component in (self.root, *self.root.parents):
            try:
                metadata = os.lstat(component)
            except OSError as error:
                raise UnsafeLocalPath("部署根父组件不可机械验证") from error
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise UnsafeLocalPath("部署根或父组件是 symlink/reparse")
            if not stat.S_ISDIR(metadata.st_mode):
                raise UnsafeLocalPath("部署根或父组件不是普通目录")

    def _assert_lexical_child(self, path: Path) -> tuple[str, ...]:
        if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
            raise UnsafeLocalPath("目标必须是 root 内绝对规范路径")
        root_text = str(self.root)
        path_text = str(path)
        if path_text == root_text:
            return ()
        if not path_text.startswith(root_text + os.sep):
            raise UnsafeLocalPath("目标逃逸精确部署根")
        try:
            return path.relative_to(self.root).parts
        except ValueError as error:
            raise UnsafeLocalPath("目标逃逸精确部署根") from error

    @staticmethod
    def _entries_by_fold(parent: Path) -> Mapping[str, str]:
        entries: dict[str, str] = {}
        try:
            with os.scandir(parent) as iterator:
                for entry in iterator:
                    folded = entry.name.casefold()
                    previous = entries.get(folded)
                    if previous is not None and previous != entry.name:
                        raise UnsafeLocalPath("目录存在 case-fold 名称碰撞")
                    entries[folded] = entry.name
        except OSError as error:
            raise UnsafeLocalPath("无法检查路径组件大小写") from error
        return entries

    def preflight(
        self,
        path: Path,
        *,
        expected_kind: str | None = None,
        allow_absent: bool = True,
    ) -> os.stat_result | None:
        self._verify_exact_existing_root()
        parts = self._assert_lexical_child(path)
        current = self.root
        if not parts:
            metadata = os.lstat(current)
            return metadata
        for index, part in enumerate(parts):
            parent_metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or stat.S_ISLNK(parent_metadata.st_mode)
                or _is_reparse(parent_metadata)
            ):
                raise UnsafeLocalPath("目标父组件不是普通非 reparse 目录")
            actual = self._entries_by_fold(current).get(part.casefold())
            if actual is None:
                if allow_absent:
                    return None
                raise UnsafeLocalPath("目标路径不存在")
            if actual != part:
                raise UnsafeLocalPath("目标组件大小写不是 exact path")
            current = current / actual
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise UnsafeLocalPath("目标组件是 symlink/reparse")
            if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                raise UnsafeLocalPath("目标中间组件不是目录")
        metadata = os.lstat(current)
        if expected_kind == "file" and not stat.S_ISREG(metadata.st_mode):
            raise UnsafeLocalPath("目标不是普通文件")
        if expected_kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
            raise UnsafeLocalPath("目标不是普通目录")
        return metadata

    def create_layout(self) -> None:
        targets = [self.root.joinpath(*relative.split("/")) for relative in _LAYOUT_DIRECTORIES]
        # 所有 prospective 目录先完成机械预检，随后才允许第一次 mkdir。
        for target in targets:
            self.preflight(target, expected_kind="directory", allow_absent=True)
        with _BoundDirectory(self, self.root) as root_guard:
            for target in targets:
                metadata = self.preflight(
                    target, expected_kind="directory", allow_absent=True
                )
                if metadata is None:
                    try:
                        with _BoundDirectory(
                            self,
                            target.parent,
                            protect_rename=target.parent != self.root,
                        ) as parent:
                            # root guard + 真实父句柄保持到 mkdir/复验结束。
                            if self.preflight(
                                target,
                                expected_kind="directory",
                                allow_absent=True,
                            ) is not None:
                                raise UnsafeLocalPath("布局目录在 mkdir 前出现第三值")
                            parent.mkdir(target.name, 0o700)
                    except OSError as error:
                        raise UnsafeLocalPath("无法建立批准的布局目录") from error
                self.preflight(target, expected_kind="directory", allow_absent=False)

            lock_path = self.root / "locks" / "local_deployment.lock"
            observed = self.preflight(lock_path, expected_kind="file", allow_absent=True)
            if observed is None:
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_SYNC", 0)
                with _BoundDirectory(self, lock_path.parent) as lock_parent:
                    descriptor = lock_parent.open_file(lock_path.name, flags, 0o600)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    lock_parent.flush()
            lock_metadata = self.preflight(lock_path, expected_kind="file", allow_absent=False)
            if lock_metadata is None or getattr(lock_metadata, "st_nlink", 1) != 1:
                raise UnsafeLocalPath("持久 lock 文件不是普通独占文件")


@dataclass(frozen=True, slots=True)
class LocalDeploymentLayout:
    root: Path

    @property
    def incoming(self) -> Path:
        return self.root / "incoming"

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def control(self) -> Path:
        return self.root / "control"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def audit(self) -> Path:
        return self.root / "audit"

    @property
    def journals(self) -> Path:
        return self.audit / "deployment_attempts"

    @property
    def receipts(self) -> Path:
        return self.audit / "receipts"

    @property
    def events(self) -> Path:
        return self.audit / "events"

    @property
    def locks(self) -> Path:
        return self.root / "locks"

    @property
    def temporary(self) -> Path:
        return self.root / "tmp"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def active_release(self) -> Path:
        return self.control / "active_release.json"

    @property
    def local_prior_binding(self) -> Path:
        return self.control / "local_prior_binding.json"

    @property
    def deployment_lock(self) -> Path:
        return self.locks / "local_deployment.lock"


class CrashReleasedFileLock:
    """由 OS 文件句柄持有、owner crash 后自动释放的全局锁。"""

    def __init__(
        self,
        *,
        path: Path,
        safe_root: _SafeRoot,
        allow_posix_test_only: bool,
        authority_token: object,
    ):
        self.path = path
        self._safe_root = safe_root
        self._allow_posix_test_only = allow_posix_test_only
        self._authority_token = authority_token
        self._descriptor: int | None = None
        self._descriptor_expected_identity: os.stat_result | None = None
        self._descriptor_identity: os.stat_result | None = None
        # descriptor 数字可在 close 后立即复用；dev/ino 也不能区分同一文件的两次
        # open。Windows 产品路径因此为原 CRT fd 立即建立 DuplicateHandle guard，
        # 并只用 CompareObjectHandles 判断后续同号 fd 是否仍是原 open instance。
        # POSIX 只是 test-only，缺少可移植的 open-file-description oracle；其
        # ambiguous same-file close 会保留为 fail-closed，而不猜测后重试数字。
        self._descriptor_instance_guard_required = False
        self._descriptor_instance_guard: int | None = None
        self._descriptor_instance_guard_identity: os.stat_result | None = None
        self._descriptor_close_ambiguous = False
        self._descriptor_instance_guard_close_ambiguous = False
        # False/True 分别表示机械证明未取得/已取得；None 只用于 Win32
        # close-source syscall 结果不可判定的 owner-crash-only 终态。
        self._kernel_lock_acquired: bool | None = False
        self._retired_guard_close_audit_sha256: str | None = None
        self._owner_crash_only_reason: str | None = None
        self._acquire_parent: _BoundDirectory | None = None
        self._bound_parent: _BoundDirectory | None = None
        self._bound_root: _BoundDirectory | None = None
        self._owner_thread: int | None = None
        self._owner_pid: int | None = None
        self._acquisition_epoch: _LockAcquisitionEpoch | None = None
        self._dependent_workspaces: set[LockedAttemptWorkspace] = set()
        self._shared_directory_guards: dict[Path, _BoundDirectory] = {}
        self._release_phase = "idle"
        self._process_reservation = False

    @property
    def held(self) -> bool:
        return self._release_phase != "idle" or self._has_tracked_resources()

    def _registry_key(self) -> str:
        return os.path.normcase(str(self.path))

    def _reserve_process_acquisition(self) -> None:
        key = self._registry_key()
        with _PROCESS_LOCK_REGISTRY_GUARD:
            owner = _PROCESS_LOCK_REGISTRY.get(key)
            if owner is not None and owner is not self:
                raise DeploymentLockBusy(
                    "同进程另一 lock object 正在 acquiring/live/closing"
                )
            _PROCESS_LOCK_REGISTRY[key] = self
            self._process_reservation = True

    def _release_process_acquisition(self) -> None:
        if not self._process_reservation:
            return
        key = self._registry_key()
        with _PROCESS_LOCK_REGISTRY_GUARD:
            if _PROCESS_LOCK_REGISTRY.get(key) is not self:
                raise LocalDeploymentPersistenceError(
                    "process lock reservation identity 漂移"
                )
            _PROCESS_LOCK_REGISTRY.pop(key)
            self._process_reservation = False

    def _has_tracked_resources(self) -> bool:
        return bool(
            self._descriptor is not None
            or self._descriptor_expected_identity is not None
            or self._descriptor_identity is not None
            or self._descriptor_instance_guard_required
            or self._descriptor_instance_guard is not None
            or self._descriptor_instance_guard_identity is not None
            or self._descriptor_close_ambiguous
            or self._descriptor_instance_guard_close_ambiguous
            or self._kernel_lock_acquired is not False
            or self._retired_guard_close_audit_sha256 is not None
            or self._owner_crash_only_reason is not None
            or self._acquire_parent is not None
            or self._bound_parent is not None
            or self._bound_root is not None
            or self._dependent_workspaces
            or self._shared_directory_guards
            or self._process_reservation
        )

    def _reset_idle_after_proven_cleanup(self) -> None:
        if any(
            (
                self._descriptor is not None,
                self._descriptor_expected_identity is not None,
                self._descriptor_identity is not None,
                self._descriptor_instance_guard_required,
                self._descriptor_instance_guard is not None,
                self._descriptor_instance_guard_identity is not None,
                self._descriptor_close_ambiguous,
                self._descriptor_instance_guard_close_ambiguous,
                self._kernel_lock_acquired is not False,
                self._retired_guard_close_audit_sha256 is not None,
                self._owner_crash_only_reason is not None,
                self._acquire_parent is not None,
                self._bound_parent is not None,
                self._bound_root is not None,
                bool(self._dependent_workspaces),
                bool(self._shared_directory_guards),
            )
        ):
            raise LocalDeploymentPersistenceError(
                "lock 仍有资源，不得转回 idle"
            )
        self._acquisition_epoch = None
        self._owner_pid = None
        self._owner_thread = None
        self._release_process_acquisition()
        self._release_phase = "idle"

    @staticmethod
    def _require_windows_open_instance_support() -> None:
        """在打开 lock fd 前确认产品 OS 有 exact open-object API。"""

        if os.name != "nt":
            return
        import ctypes

        try:
            getattr(ctypes.WinDLL("kernelbase"), "CompareObjectHandles")
            getattr(ctypes.WinDLL("kernel32"), "DuplicateHandle")
        except (AttributeError, OSError) as error:
            raise UnsafeLocalPath(
                "Windows 产品主机缺少 CompareObjectHandles/DuplicateHandle"
            ) from error

    @staticmethod
    def _windows_duplicate_handle_call(
        raw_handle: int,
        output_handle: object,
    ) -> bool:
        """唯一 raw acquisition syscall seam；output 由 state owner 持有。"""

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.DuplicateHandle.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.DuplicateHandle.restype = wintypes.BOOL
        return bool(kernel32.DuplicateHandle(
            kernel32.GetCurrentProcess(),
            wintypes.HANDLE(raw_handle),
            kernel32.GetCurrentProcess(),
            ctypes.byref(output_handle),
            0,
            False,
            0x00000002,  # DUPLICATE_SAME_ACCESS
        ))

    def _duplicate_windows_descriptor_instance(self, descriptor: int) -> None:
        """复制并在任何 syscall 异常可见前单调登记 output guard。"""

        import ctypes
        import msvcrt
        from ctypes import wintypes

        if self._descriptor_instance_guard is not None:
            return
        raw_handle = msvcrt.get_osfhandle(descriptor)
        invalid = ctypes.c_void_p(-1).value
        if raw_handle in {-1, invalid}:
            raise OSError(errno.EBADF, "CRT descriptor 没有有效 OS HANDLE")
        duplicated = wintypes.HANDLE()
        status: bool | None = None
        try:
            status = self._windows_duplicate_handle_call(
                int(raw_handle), duplicated
            )
        finally:
            # raw wrapper 可能在 syscall 已写 output 后抛错。finally 在该异常
            # 对 caller 可见前先提交 tracking；false+nonempty 同样必须登记。
            output = duplicated.value
            if output not in {None, invalid}:
                if self._descriptor_instance_guard not in {None, int(output)}:
                    # 本 helper 只允许在无 guard 时进入；若字段被异步污染，不能
                    # 遗失新 output，也不能安全选一个整数继续。进程 crash 是唯一
                    # 能同时闭合这些未知资源的边界。
                    self._enter_owner_crash_only(
                        reason="duplicate_output_tracking_conflict",
                    )
                else:
                    self._descriptor_instance_guard = int(output)
        if not status:
            raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def _windows_descriptor_instance_relation(
        descriptor: int,
        instance_guard: int,
    ) -> str:
        """返回 ``same``/``different``/``gone``，其他 API 错误一律拒绝。"""

        import ctypes
        import msvcrt
        from ctypes import wintypes

        try:
            raw_handle = msvcrt.get_osfhandle(descriptor)
        except OSError as error:
            if error.errno == errno.EBADF:
                return "gone"
            raise LocalDeploymentPersistenceError(
                "无法取得当前 CRT descriptor 的 OS HANDLE"
            ) from error
        invalid = ctypes.c_void_p(-1).value
        if raw_handle in {-1, invalid}:
            return "gone"
        kernelbase = ctypes.WinDLL("kernelbase", use_last_error=True)
        kernelbase.CompareObjectHandles.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
        )
        kernelbase.CompareObjectHandles.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        if kernelbase.CompareObjectHandles(
            wintypes.HANDLE(raw_handle),
            wintypes.HANDLE(instance_guard),
        ):
            return "same"
        error = ctypes.get_last_error()
        if error == 1656:  # ERROR_NOT_SAME_OBJECT
            return "different"
        raise LocalDeploymentPersistenceError(
            f"CompareObjectHandles 无法证明 descriptor open instance: {error}"
        )

    @staticmethod
    def _windows_duplicate_close_source_call(instance_guard: int) -> bool:
        """唯一 raw CLOSE_SOURCE syscall seam。"""

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.DuplicateHandle.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        kernel32.DuplicateHandle.restype = wintypes.BOOL
        # target process 与 target handle 都为 NULL；本调用只请求关闭 source。
        return bool(kernel32.DuplicateHandle(
            kernel32.GetCurrentProcess(),
            wintypes.HANDLE(instance_guard),
            None,
            None,
            0,
            False,
            0x00000001,  # DUPLICATE_CLOSE_SOURCE
        ))

    def _enter_owner_crash_only(self, *, reason: str) -> None:
        """永久撤销全部 numeric close authority，只允许进程退出回收。

        audit seal 只绑定非敏感状态和 reason；不得保存可再次传给 Win32/CRT 的
        raw handle/fd 数字。kernel 锁事实不可判定时用 ``None``，禁止以 bool 猜测。
        """

        material = {
            "schema_version": "qrh-lock-retired-handle/v1",
            "reason": reason,
            "owner_pid": self._owner_pid,
            "owner_thread": self._owner_thread,
            "previous_phase": self._release_phase,
        }
        self._retired_guard_close_audit_sha256 = hashlib.sha256(
            _identity.canonical_bytes(material)
        ).hexdigest()
        self._owner_crash_only_reason = reason
        self._descriptor = None
        self._descriptor_identity = None
        self._descriptor_close_ambiguous = False
        self._descriptor_instance_guard = None
        self._descriptor_instance_guard_identity = None
        self._descriptor_instance_guard_required = False
        self._descriptor_instance_guard_close_ambiguous = False
        self._kernel_lock_acquired = None
        self._acquisition_epoch = None
        self._release_phase = "owner_crash_only"

    def _close_windows_descriptor_instance_guard(self) -> None:
        """CLOSE_SOURCE 与 Python tracking 在同一 state owner 内单调提交。"""

        instance_guard = self._descriptor_instance_guard
        if instance_guard is None:
            raise LocalDeploymentPersistenceError(
                "Windows instance guard 不存在"
            )
        try:
            # DuplicateHandle 文档保证 syscall 返回时 source 已关闭，不论 BOOL。
            # raw seam 若抛错则无法判断 syscall 是否发生，必须退休整数 authority。
            self._windows_duplicate_close_source_call(instance_guard)
        except BaseException as error:
            self._enter_owner_crash_only(
                reason="duplicate_close_source_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "CLOSE_SOURCE 结果不可判定；lock 进入 owner-crash-only"
            ) from error
        # syscall 已返回：在任何 outer wrapper 异常可见前，单调撤销整数 authority
        # 与 kernel-held 声明。outer wrapper 再抛也不能把旧数字恢复成可执行句柄。
        self._descriptor_instance_guard = None
        self._descriptor_instance_guard_identity = None
        self._descriptor_instance_guard_close_ambiguous = False
        self._descriptor_instance_guard_required = False
        self._kernel_lock_acquired = False

    def _ensure_descriptor_instance_guard(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            raise LocalDeploymentPersistenceError(
                "无 descriptor 时不得创建 open-instance guard"
            )
        if self._descriptor_instance_guard is not None:
            return
        if not self._descriptor_instance_guard_required:
            raise LocalDeploymentPersistenceError(
                "descriptor 未登记 open-instance guard acquisition"
            )
        if os.name == "nt":
            self._duplicate_windows_descriptor_instance(descriptor)
            # state-owning helper 必须已登记；outer wrapper post-return 异常也
            # 不会让已生成 output 回到未登记状态。
            if (
                self._descriptor_instance_guard is None
                and self._release_phase != "owner_crash_only"
            ):
                raise LocalDeploymentPersistenceError(
                    "DuplicateHandle 未提交 output tracking"
                )
            return
        if not self._allow_posix_test_only:
            raise UnsafeLocalPath("POSIX open-instance guard 只允许 test-only")
        guard = os.dup(descriptor)
        self._descriptor_instance_guard = guard
        # guard fd 已先登记；fstat 即使失败也不会遗失资源。
        self._descriptor_instance_guard_identity = os.fstat(guard)

    def _clear_descriptor_number(self) -> None:
        self._descriptor = None
        self._descriptor_identity = None
        self._descriptor_close_ambiguous = False

    def _close_descriptor_instance_guard(self) -> None:
        guard = self._descriptor_instance_guard
        if guard is None:
            if self._descriptor_instance_guard_required:
                raise LocalDeploymentPersistenceError(
                    "open-instance guard 尚未取得，不得伪造 cleanup"
                )
            return
        if os.name == "nt":
            try:
                self._close_windows_descriptor_instance_guard()
            except BaseException:
                if self._release_phase == "owner_crash_only":
                    raise
                if (
                    self._descriptor_instance_guard is None
                    and not self._descriptor_instance_guard_required
                    and self._kernel_lock_acquired is False
                ):
                    # outer wrapper 在 state-owning helper 已提交后抛错；真实状态
                    # 已单调闭合，不能让 wrapper 反向恢复旧 authority。
                    return
                raise
            return

        identity = self._descriptor_instance_guard_identity
        if identity is None:
            try:
                identity = os.fstat(guard)
            except OSError as error:
                if error.errno == errno.EBADF:
                    self._descriptor_instance_guard = None
                    self._descriptor_instance_guard_close_ambiguous = False
                    self._descriptor_instance_guard_required = False
                    return
                raise LocalDeploymentPersistenceError(
                    "无法取得 POSIX instance guard identity"
                ) from error
            self._descriptor_instance_guard_identity = identity
        if self._descriptor_instance_guard_close_ambiguous:
            try:
                observed = os.fstat(guard)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise LocalDeploymentPersistenceError(
                        "无法证明 POSIX instance guard 是否仍存在"
                    ) from error
                self._descriptor_instance_guard = None
                self._descriptor_instance_guard_identity = None
                self._descriptor_instance_guard_close_ambiguous = False
                self._descriptor_instance_guard_required = False
                return
            if _same_file_identity(observed, identity):
                raise LocalDeploymentPersistenceError(
                    "POSIX instance guard close 结果歧义；test-only adapter 永久 fail-closed"
                )
            # different file identity 是强否定证明；不得关闭同号 replacement。
            self._descriptor_instance_guard = None
            self._descriptor_instance_guard_identity = None
            self._descriptor_instance_guard_close_ambiguous = False
            self._descriptor_instance_guard_required = False
            return
        try:
            os.close(guard)
        except OSError as error:
            try:
                observed = os.fstat(guard)
            except OSError as proof_error:
                if proof_error.errno == errno.EBADF:
                    self._descriptor_instance_guard = None
                    self._descriptor_instance_guard_identity = None
                    self._descriptor_instance_guard_required = False
                    return
                raise LocalDeploymentPersistenceError(
                    "无法证明 POSIX instance guard close 结果"
                ) from proof_error
            if not _same_file_identity(observed, identity):
                self._descriptor_instance_guard = None
                self._descriptor_instance_guard_identity = None
                self._descriptor_instance_guard_required = False
                return
            self._descriptor_instance_guard_close_ambiguous = True
            raise LocalDeploymentPersistenceError(
                "POSIX instance guard close 结果歧义；保留 fail-closed tracking"
            ) from error
        self._descriptor_instance_guard = None
        self._descriptor_instance_guard_identity = None
        self._descriptor_instance_guard_close_ambiguous = False
        self._descriptor_instance_guard_required = False

    def acquire(self) -> "CrashReleasedFileLock":
        if self.held or self._release_phase != "idle":
            raise DeploymentLockBusy("同一 lock object 不可重入")
        if self._has_tracked_resources():
            raise DeploymentLockBusy("lock 仍有未注销的 attempt workspace 资源")
        self._reserve_process_acquisition()
        self._owner_pid = os.getpid()
        self._owner_thread = threading.get_ident()
        self._release_phase = "acquiring"
        try:
            expected = self._safe_root.preflight(
                self.path,
                expected_kind="file",
                allow_absent=False,
            )
            if expected is None:
                raise UnsafeLocalPath("持久 lock 文件不存在")
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            self._descriptor_expected_identity = expected
            self._require_windows_open_instance_support()

            # 每个 fallible enter/open 前先把容器或刚返回的 descriptor 登记到
            # lock object；acquire 的异常路径因此可复用 release 状态机重试。
            self._acquire_parent = _BoundDirectory(
                self._safe_root,
                self.path.parent,
                protect_rename=False,
            )
            self._acquire_parent.__enter__()
            try:
                descriptor = self._acquire_parent.open_file(
                    self.path.name, flags, 0o600
                )
            except OSError as error:
                raise UnsafeLocalPath("无法安全打开持久 lock 文件") from error
            self._descriptor = descriptor
            self._descriptor_instance_guard_required = True
            # fd 数字一经返回，先登记并取得同一 kernel open object 的 guard；
            # 在此之前禁止 fstat、close 或其他可能令数字被复用的 fallible 步骤。
            self._ensure_descriptor_instance_guard()
            # expected path identity 只用于稍后的 open-vs-path 核对，绝不冒充
            # opened descriptor identity。首次 fstat 失败时 cleanup 必须先重试只读
            # identity acquisition；在 actual identity 取得前禁止 ambiguous close。
            self._descriptor_identity = None
            if os.name == "nt":
                instance_guard = self._descriptor_instance_guard
                if instance_guard is None or self._windows_descriptor_instance_relation(
                    descriptor, instance_guard
                ) != "same":
                    raise UnsafeLocalPath(
                        "lock descriptor 在首次 identity 探针前已不是原 open instance"
                    )
            opened = os.fstat(descriptor)
            self._descriptor_identity = opened
            observed = self._safe_root.preflight(
                self.path,
                expected_kind="file",
                allow_absent=False,
            )
            if (
                observed is None
                or not _same_file_identity(expected, opened)
                or not _same_file_identity(opened, observed)
                or not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or getattr(opened, "st_nlink", 1) != 1
            ):
                raise UnsafeLocalPath("lock 路径在打开期间发生身份漂移")
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    if not self._allow_posix_test_only:
                        raise UnsafeLocalPath("POSIX lock 只允许 test-only")
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._kernel_lock_acquired = True
            except (OSError, BlockingIOError) as error:
                raise DeploymentLockBusy("全局部署锁正被其他 owner 持有") from error

            self._bound_root = _BoundDirectory(
                self._safe_root,
                self._safe_root.root,
            )
            self._bound_root.__enter__()
            self._bound_parent = _BoundDirectory(
                self._safe_root,
                self.path.parent,
            )
            self._bound_parent.__enter__()

            self._acquire_parent.__exit__(None, None, None)
            if not self._acquire_parent._fully_closed():
                raise LocalDeploymentPersistenceError(
                    "临时 locks parent guard 未机械闭合"
                )
            self._acquire_parent = None

            # epoch 是 live capability，不得在任何 pre-live cleanup 尚未闭合时创建。
            self._acquisition_epoch = _LockAcquisitionEpoch()
            self._release_phase = "live"
            return self
        except BaseException as acquisition_error:
            if self._release_phase != "owner_crash_only":
                self._release_phase = "acquire_failed"
                try:
                    self._release_owned_resources()
                except BaseException:
                    # 持续 close 故障保留 acquire_failed + owner + exact tracking；
                    # 调用者可在故障解除后由同 owner显式 release() 重试。
                    pass
            raise acquisition_error

    def assert_held(self, *, authority_token: object) -> None:
        if (
            self._descriptor is None
            or self._release_phase != "live"
            or authority_token is not self._authority_token
            or self._owner_pid != os.getpid()
            or self._owner_thread != threading.get_ident()
            or self._acquisition_epoch is None
        ):
            raise DeploymentLockBusy("操作必须持有同一实例的全局部署锁")

    def _assert_epoch_owner(
        self,
        *,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
    ) -> None:
        if (
            self._descriptor is None
            or self._release_phase not in {"live", "closing"}
            or authority_token is not self._authority_token
            or self._owner_pid != os.getpid()
            or self._owner_thread != threading.get_ident()
            or self._acquisition_epoch is None
            or acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "close/retry 必须属于同一 lock acquisition owner"
            )

    def _capture_acquisition_epoch(
        self,
        *,
        authority_token: object,
    ) -> _LockAcquisitionEpoch:
        self.assert_held(authority_token=authority_token)
        epoch = self._acquisition_epoch
        if epoch is None:
            raise DeploymentLockBusy("lock acquisition epoch 不存在")
        return epoch

    def _assert_epoch_held(
        self,
        *,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
    ) -> None:
        self.assert_held(authority_token=authority_token)
        if acquisition_epoch is not self._acquisition_epoch:
            raise DeploymentLockBusy("attempt workspace 不属于当前 lock acquisition")

    def _register_workspace(
        self,
        workspace: LockedAttemptWorkspace,
        *,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
    ) -> None:
        self._assert_epoch_held(
            authority_token=authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        self._dependent_workspaces.add(workspace)

    def _shared_directory_guard(
        self,
        path: Path,
        *,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
    ) -> _BoundDirectory:
        self._assert_epoch_held(
            authority_token=authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        existing = self._shared_directory_guards.get(path)
        if existing is not None:
            return existing
        guard = _BoundDirectory(self._safe_root, path)
        self._shared_directory_guards[path] = guard
        try:
            guard.__enter__()
        except BaseException:
            if guard._fully_closed():
                self._shared_directory_guards.pop(path, None)
            raise
        return guard

    def _unregister_workspace(
        self,
        workspace: LockedAttemptWorkspace,
        *,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
    ) -> None:
        self._assert_epoch_owner(
            authority_token=authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        if workspace not in self._dependent_workspaces:
            raise DeploymentLockBusy("attempt workspace 未注册到当前 lock acquisition")
        self._dependent_workspaces.remove(workspace)

    def _release_owned_resources(self) -> None:
        if self._release_phase == "live":
            self._release_phase = "closing"
        elif self._release_phase not in {
            "acquiring",
            "acquire_failed",
            "closing",
        }:
            raise LocalDeploymentPersistenceError("lock release phase 非法")
        epoch = self._acquisition_epoch
        close_error: BaseException | None = None
        if self._dependent_workspaces and epoch is None:
            close_error = LocalDeploymentPersistenceError(
                "pre-live lock 不得持有 dependent workspace"
            )
        elif epoch is not None:
            for workspace in tuple(self._dependent_workspaces):
                try:
                    workspace._close_for_lock_release(
                        lock=self,
                        acquisition_epoch=epoch,
                        _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                    )
                except BaseException as error:  # fail closed before kernel unlock
                    if close_error is None:
                        close_error = error
        for path, guard in tuple(self._shared_directory_guards.items())[::-1]:
            try:
                guard.__exit__(None, None, None)
            except BaseException as error:
                if close_error is None:
                    close_error = error
            else:
                if guard._fully_closed():
                    self._shared_directory_guards.pop(path, None)
                elif close_error is None:
                    close_error = UnsafeLocalPath(
                        "shared directory guard 未机械闭合"
                    )
        if (
            close_error is not None
            or self._dependent_workspaces
            or self._shared_directory_guards
        ):
            raise LocalDeploymentPersistenceError(
                "lock dependent workspace 在 kernel unlock 前无法闭合"
            ) from close_error
        close_error = None
        for attribute in (
            "_acquire_parent",
            "_bound_parent",
            "_bound_root",
        ):
            guard = getattr(self, attribute)
            if guard is None:
                continue
            try:
                guard.__exit__(None, None, None)
            except BaseException as error:
                if close_error is None:
                    close_error = error
                continue
            if guard._fully_closed():
                setattr(self, attribute, None)
            elif close_error is None:
                close_error = UnsafeLocalPath(
                    "lock root/locks guard 未机械闭合"
                )
        if (
            close_error is not None
            or self._acquire_parent is not None
            or self._bound_root is not None
            or self._bound_parent is not None
        ):
            raise LocalDeploymentPersistenceError(
                "lock directory guards 在 kernel lock close 前无法闭合"
            ) from close_error

        descriptor = self._descriptor
        if descriptor is None:
            if self._descriptor_identity is not None:
                raise LocalDeploymentPersistenceError(
                    "lock descriptor number 与 identity tracking 不一致"
                )
            if self._descriptor_instance_guard is not None:
                self._close_descriptor_instance_guard()
                self._kernel_lock_acquired = False
            elif self._descriptor_instance_guard_required:
                raise LocalDeploymentPersistenceError(
                    "descriptor number 已消失但 open-instance guard 尚未取得"
                )
            if self._kernel_lock_acquired:
                raise LocalDeploymentPersistenceError(
                    "open-instance guard 已闭合但 kernel lock tracking 仍为 true"
                )
            # open 失败前已登记的 expected path identity 不是 kernel resource。
            self._descriptor_expected_identity = None
            self._reset_idle_after_proven_cleanup()
            return
        self._ensure_descriptor_instance_guard()
        instance_guard = self._descriptor_instance_guard
        if instance_guard is None:
            raise LocalDeploymentPersistenceError("lock 缺 open-instance guard")

        if os.name == "nt":
            relation = self._windows_descriptor_instance_relation(
                descriptor, instance_guard
            )
            if relation != "same":
                # descriptor 已关闭或同号复用。CompareObjectHandles 是
                # open-instance 强证明；绝不关闭 replacement 数字。
                self._clear_descriptor_number()
        elif self._descriptor_close_ambiguous:
            try:
                observed = os.fstat(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise LocalDeploymentPersistenceError(
                        "无法证明 POSIX ambiguous descriptor 是否仍存在"
                    ) from error
                self._clear_descriptor_number()
            else:
                identity = self._descriptor_identity
                if identity is not None and not _same_file_identity(
                    observed, identity
                ):
                    # different inode 是强否定；不得关闭同号 replacement。
                    self._clear_descriptor_number()
                else:
                    raise LocalDeploymentPersistenceError(
                        "POSIX same-file descriptor close 结果歧义；test-only adapter 永久 fail-closed"
                    )

        descriptor = self._descriptor
        if descriptor is not None:
            identity = self._descriptor_identity
            if identity is None:
                try:
                    identity = os.fstat(descriptor)
                except OSError as error:
                    # guard 已经登记，但 Round5 的 file-identity seal 仍必须在
                    # close 前取得；失败时保持 owner/process reservation。
                    raise LocalDeploymentPersistenceError(
                        "无法取得 lock opened-descriptor exact identity；保留供 owner retry"
                    ) from error
                self._descriptor_identity = identity
            if os.name == "nt":
                relation = self._windows_descriptor_instance_relation(
                    descriptor, instance_guard
                )
                if relation != "same":
                    self._clear_descriptor_number()
            if self._descriptor is not None:
                try:
                    # Windows byte-range lock 由原 file object 与 duplicate guard
                    # 共同维持；CRT fd close 后 guard 未闭合前 contender 仍 Busy。
                    os.close(descriptor)
                except OSError as error:
                    if os.name == "nt":
                        relation = self._windows_descriptor_instance_relation(
                            descriptor, instance_guard
                        )
                        if relation == "same":
                            raise LocalDeploymentPersistenceError(
                                "原 lock descriptor 未关闭，保留 tracking 供 retry"
                            ) from error
                        self._clear_descriptor_number()
                    else:
                        try:
                            observed = os.fstat(descriptor)
                        except OSError as proof_error:
                            if proof_error.errno == errno.EBADF:
                                self._clear_descriptor_number()
                            else:
                                raise LocalDeploymentPersistenceError(
                                    "无法证明 POSIX descriptor close 结果"
                                ) from proof_error
                        else:
                            if not _same_file_identity(observed, identity):
                                self._clear_descriptor_number()
                            else:
                                self._descriptor_close_ambiguous = True
                                raise LocalDeploymentPersistenceError(
                                    "POSIX same-file descriptor close 结果歧义；保留 fail-closed tracking"
                                ) from error
                else:
                    self._clear_descriptor_number()

        if self._descriptor is not None:
            raise LocalDeploymentPersistenceError(
                "lock descriptor number 尚未机械闭合"
            )
        self._close_descriptor_instance_guard()
        self._descriptor_expected_identity = None
        self._kernel_lock_acquired = False
        self._reset_idle_after_proven_cleanup()

    def release(self) -> None:
        if self._release_phase == "idle":
            if self._has_tracked_resources():
                raise LocalDeploymentPersistenceError(
                    "idle lock 仍有未登记生命周期的资源"
                )
            return
        if (
            self._owner_pid != os.getpid()
            or self._owner_thread != threading.get_ident()
        ):
            raise DeploymentLockBusy("lock 只能由 acquisition owner 释放")
        if self._release_phase == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "retired handle outcome 不可判定；只允许 owner 进程退出回收"
            )
        self._release_owned_resources()

    def __enter__(self) -> "CrashReleasedFileLock":
        return self.acquire()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def _canonical_read(
    path: Path,
    *,
    safe_root: _SafeRoot,
    validator: Callable[[object], Mapping[str, object]],
    label: str,
) -> CanonicalJsonRecord | None:
    metadata = safe_root.preflight(path, expected_kind="file", allow_absent=True)
    if metadata is None:
        return None
    if getattr(metadata, "st_nlink", 1) != 1:
        raise UnsafeLocalPath(f"{label} 不得是 hardlink")
    before = metadata
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LocalDeploymentPersistenceError(f"无法读取 {label}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not _same_file_identity(before, opened)
            or not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or getattr(opened, "st_nlink", 1) != 1
        ):
            raise UnsafeLocalPath(f"{label} open-handle 身份漂移")
        blocks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        raw = b"".join(blocks)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = safe_root.preflight(path, expected_kind="file", allow_absent=False)
    if (
        after is None
        or not _same_file_identity(before, opened_after)
        or not _same_file_identity(opened_after, after)
        or opened.st_size != opened_after.st_size
        or opened.st_mtime_ns != opened_after.st_mtime_ns
    ):
        raise UnsafeLocalPath(f"{label} 在读取期间发生身份漂移")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalDeploymentPersistenceError(f"{label} 不是 UTF-8 JSON") from error
    if _identity.canonical_bytes(value) != raw:
        raise LocalDeploymentPersistenceError(f"{label} 不是 exact canonical JSON")
    try:
        validated = validator(value)
    except Exception as error:
        raise LocalDeploymentPersistenceError(f"{label} schema/hash 无效") from error
    return CanonicalJsonRecord(
        value=validated,
        sha256=hashlib.sha256(raw).hexdigest(),
        raw=raw,
    )


def _write_through_replace(
    path: Path,
    raw: bytes,
    *,
    safe_root: _SafeRoot,
    temporary_directory: Path,
) -> None:
    with _BoundDirectory(safe_root, path.parent) as target_parent, _BoundDirectory(
        safe_root, temporary_directory
    ) as temporary_parent:
        _write_through_replace_bound(
            path,
            raw,
            safe_root=safe_root,
            temporary_directory=temporary_directory,
            target_parent=target_parent,
            temporary_parent=temporary_parent,
        )


def _write_through_replace_bound(
    path: Path,
    raw: bytes,
    *,
    safe_root: _SafeRoot,
    temporary_directory: Path,
    target_parent: _BoundDirectory,
    temporary_parent: _BoundDirectory,
) -> None:
    """Durable replace through already lock-bound parent directory owners."""

    if (
        type(target_parent) is not _BoundDirectory
        or type(temporary_parent) is not _BoundDirectory
        or target_parent.path != path.parent
        or temporary_parent.path != temporary_directory
        or target_parent._safe_root is not safe_root
        or temporary_parent._safe_root is not safe_root
        or not target_parent._windows_handles
        and os.name == "nt"
        or not temporary_parent._windows_handles
        and os.name == "nt"
        or target_parent._descriptor is None
        and os.name != "nt"
        or temporary_parent._descriptor is None
        and os.name != "nt"
    ):
        raise UnsafeLocalPath("CAS durable replace 缺 exact live bound parents")
    safe_root.preflight(path.parent, expected_kind="directory", allow_absent=False)
    safe_root.preflight(
        temporary_directory, expected_kind="directory", allow_absent=False
    )
    safe_root.preflight(path, expected_kind="file", allow_absent=True)
    temporary = temporary_directory / f".{path.name}.{uuid.uuid4().hex}.tmp"
    safe_root.preflight(temporary, expected_kind="file", allow_absent=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_SYNC", 0)
    descriptor: int | None = None
    try:
        # 目录句柄已绑定；下列首次写不会重新信任可替换的 parent path。
        descriptor = temporary_parent.open_file(temporary.name, flags, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short canonical JSON write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        safe_root.preflight(path, expected_kind="file", allow_absent=True)
        target_parent.replace_from(
            temporary_parent,
            source_name=temporary.name,
            destination_name=path.name,
        )
        final = safe_root.preflight(
            path, expected_kind="file", allow_absent=False
        )
        if final is None:
            raise LocalDeploymentPersistenceError("replace 后目标不存在")
        final_descriptor = target_parent.open_file(
            path.name,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(final_descriptor)
        finally:
            os.close(final_descriptor)
        target_parent.flush()
        temporary_parent.flush()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            if safe_root.preflight(
                temporary, expected_kind="file", allow_absent=True
            ) is not None:
                temporary_parent.unlink(temporary.name)
        except OSError:
            pass


def _write_new_bound_file(
    parent: _BoundDirectory,
    *,
    name: str,
    raw: bytes,
    label: str,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= (
        getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_SYNC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = parent.open_file(name, flags, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"short {label} write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        parent.flush()
    except OSError as error:
        raise UnsafeLocalPath(f"无法 exclusive-create {label}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class StateSqliteMemberObservation:
    """不含路径或句柄的 fixed-state SQLite 成员观察。"""

    label: str
    presence: str
    identity_scheme: str | None
    size: int | None
    mtime_ns: int | None
    bytes_sha256: str | None
    volume_identity_sha256: str | None
    file_identity_sha256: str | None


@dataclass(slots=True)
class _StateSqliteSourceMember:
    label: str
    filename: str
    present: bool
    initial: os.stat_result | None = None
    windows_handle: int | None = None
    posix_descriptor: int | None = None
    posix_close_ambiguous: bool = False


class LockedStateSqliteMemoryView:
    """由 source pin 产生的无路径、进程内 SQLite 一致视图。

    该 view 只提供内存 connection 给后续 B3 做 schema/业务检查、VACUUM 前后
    等价验证和 serialize；它本身不是 writer fence 或部署资格。
    """

    __slots__ = (
        "_source",
        "_connection",
        "_before",
        "_after",
        "_closed",
    )

    def __init__(
        self,
        *,
        source: "LockedStateSqliteSource",
        connection: sqlite3.Connection,
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_STATE_SQLITE_VIEW_TOKEN:
            raise UnsafeLocalPath("state SQLite memory view 必须由 source pin 构造")
        self._source = source
        self._connection = connection
        self._before: tuple[StateSqliteMemberObservation, ...] | None = None
        self._after: tuple[StateSqliteMemberObservation, ...] | None = None
        self._closed = False

    def __reduce__(self) -> object:
        raise TypeError("state SQLite memory view is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def database(self) -> str:
        return self._source.database

    @property
    def attempt_id(self) -> str:
        return self._source.attempt_id

    @property
    def nonce(self) -> str:
        return self._source.nonce

    @property
    def scope(self) -> str:
        return "diagnostic_source_pin_only"

    @property
    def mode(self) -> str:
        return self._source.mode

    @property
    def members(self) -> tuple[str, ...]:
        return self._source.members

    @property
    def before(self) -> tuple[StateSqliteMemberObservation, ...]:
        self._assert_live()
        if self._before is None:
            raise UnsafeLocalPath("state SQLite memory view 尚未完成 before observation")
        return self._before

    @property
    def after(self) -> tuple[StateSqliteMemberObservation, ...]:
        self._assert_live()
        if self._after is None:
            raise UnsafeLocalPath("state SQLite memory view 尚未完成 after observation")
        return self._after

    def _assert_live(self) -> None:
        if self._closed:
            raise UnsafeLocalPath("state SQLite memory view 已关闭")
        self._source._assert_live()

    def _activate(
        self,
        *,
        before: tuple[StateSqliteMemberObservation, ...],
        after: tuple[StateSqliteMemberObservation, ...],
    ) -> None:
        if before != after:
            raise UnsafeLocalPath("state SQLite source backup 前后观察漂移")
        self._before = before
        self._after = after

    def query(
        self,
        sql: str,
        parameters: Sequence[object] = (),
    ) -> tuple[tuple[object, ...], ...]:
        """执行窄只读查询；禁止 attach、DDL、DML 与写 PRAGMA。"""

        self._assert_live()
        if type(sql) is not str or not sql or len(sql) > 65536:
            raise UnsafeLocalPath("state SQLite memory query 不是闭合 SQL")
        normalized = sql.strip()
        upper = normalized.upper()
        forbidden = re.compile(
            r"\b(ATTACH|DETACH|VACUUM|INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|REINDEX)\b"
        )
        if forbidden.search(upper):
            raise UnsafeLocalPath("state SQLite memory query 只允许只读语句")
        if upper.startswith("PRAGMA"):
            scalar_read = re.fullmatch(
                r"PRAGMA\s+(?:MAIN\.)?(?:FOREIGN_KEYS|USER_VERSION|SCHEMA_VERSION|DATABASE_LIST)\s*;?",
                upper,
            )
            bounded_check = re.fullmatch(
                r"PRAGMA\s+(?:MAIN\.)?(?:INTEGRITY_CHECK|QUICK_CHECK)(?:\s*\(\s*[1-9][0-9]*\s*\))?\s*;?",
                upper,
            )
            table_read = re.fullmatch(
                r"PRAGMA\s+(?:MAIN\.)?(?:FOREIGN_KEY_CHECK|TABLE_INFO|TABLE_XINFO)(?:\s*\(\s*[^;()]+\s*\))?\s*;?",
                upper,
            )
            if "=" in normalized or not any(
                (scalar_read, bounded_check, table_read)
            ):
                raise UnsafeLocalPath("state SQLite memory query PRAGMA 不在只读闭集")
        elif not upper.startswith(("SELECT", "WITH")):
            raise UnsafeLocalPath("state SQLite memory query 只允许 SELECT/WITH/approved PRAGMA")
        if not isinstance(parameters, (tuple, list)):
            raise UnsafeLocalPath("state SQLite memory query parameters 类型错误")
        self._connection.execute("PRAGMA query_only=ON")
        try:
            return tuple(
                tuple(row)
                for row in self._connection.execute(sql, tuple(parameters)).fetchall()
            )
        except sqlite3.Error as error:
            raise UnsafeLocalPath("state SQLite memory read-only query 失败") from error

    def vacuum(self) -> None:
        """仅在无路径内存视图执行 exact VACUUM；语义等价由后续 B3 验证。"""

        self._assert_live()
        self._connection.execute("PRAGMA query_only=OFF")
        try:
            self._connection.execute("VACUUM")
        except sqlite3.Error as error:
            raise UnsafeLocalPath("state SQLite memory VACUUM 失败") from error
        finally:
            self._connection.execute("PRAGMA query_only=ON")

    def serialize(self) -> bytes:
        """序列化当前无路径内存视图；不声明 schema/业务等价或资格。"""

        self._assert_live()
        if not hasattr(self._connection, "serialize"):
            raise UnsafeLocalPath("当前 SQLite runtime 不支持 serialize")
        try:
            raw = self._connection.serialize()
        except sqlite3.Error as error:
            raise UnsafeLocalPath("state SQLite memory serialize 失败") from error
        if type(raw) is not bytes or not raw:
            raise UnsafeLocalPath("state SQLite memory serialize 没有形成 bytes")
        return raw

    def _close_from_source(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("state SQLite memory view close authority 不匹配")
        if self._closed:
            return
        self._source._close_memory_view_connection(self)

    def close(self) -> None:
        if self._closed:
            return
        self._source._close_memory_view_public(self)

    def __enter__(self) -> "LockedStateSqliteMemoryView":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedStateSqliteSource:
    """同一 lock epoch/workspace 下的 fixed-state SQLite source pin。

    产品调用者只能经 façade 用数据库枚举构造；对象不保存或公开调用者提供的
    path/root/URI，也不产生任何资格 token。
    """

    __slots__ = (
        "_persistence",
        "_workspace",
        "_lock",
        "_database",
        "_parent_guard",
        "_members",
        "_mode",
        "_source_connections",
        "_views",
        "_baseline",
        "_state",
    )

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: "LockedAttemptWorkspace",
        database: str,
        parent_guard: _BoundDirectory,
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_STATE_SQLITE_SOURCE_TOKEN:
            raise UnsafeLocalPath("state SQLite source 必须由 persistence façade 构造")
        self._persistence = persistence
        self._workspace = workspace
        self._lock = lock
        self._database = database
        self._parent_guard = parent_guard
        self._members: tuple[_StateSqliteSourceMember, ...] = ()
        self._mode = "unbound"
        self._source_connections: list[sqlite3.Connection] = []
        self._views: set[LockedStateSqliteMemoryView] = set()
        self._baseline: tuple[StateSqliteMemberObservation, ...] | None = None
        self._state = "live"

    def __reduce__(self) -> object:
        raise TypeError("state SQLite source is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def database(self) -> str:
        return self._database

    @property
    def attempt_id(self) -> str:
        return self._workspace.attempt_id

    @property
    def nonce(self) -> str:
        return self._workspace.nonce

    @property
    def scope(self) -> str:
        return "diagnostic_source_pin_only"

    @property
    def mode(self) -> str:
        self._assert_live()
        return self._mode

    @property
    def members(self) -> tuple[str, ...]:
        self._assert_live()
        return tuple(member.label for member in self._members if member.present)

    def checkpoint_unchanged(self) -> None:
        """重验 acquisition 时固定的 main/WAL/SHM open-instance 集合。"""

        self._assert_live()
        observed = self._observe_members()
        if self._baseline is None or observed != self._baseline:
            raise UnsafeLocalPath(
                "state SQLite source 自 acquisition 后发生身份/字节漂移"
            )

    def _assert_live(self) -> None:
        if self._state != "live":
            raise UnsafeLocalPath("state SQLite source 不再处于 live 状态")
        self._workspace._assert_live()

    def _path_for(self, member: _StateSqliteSourceMember) -> Path:
        return self._persistence.layout.state / member.filename

    def _preflight_presence(self) -> tuple[_StateSqliteSourceMember, ...]:
        basename = _STATE_SQLITE_DATABASES[self._database]
        journal = self._persistence.layout.state / f"{basename}-journal"
        if self._persistence._safe_root.preflight(
            journal,
            expected_kind="file",
            allow_absent=True,
        ) is not None:
            raise UnsafeLocalPath("state SQLite rollback journal 是未批准第三值")
        members: list[_StateSqliteSourceMember] = []
        for label, suffix in (("main", ""), ("wal", "-wal"), ("shm", "-shm")):
            filename = basename + suffix
            observed = self._persistence._safe_root.preflight(
                self._persistence.layout.state / filename,
                expected_kind="file",
                allow_absent=True,
            )
            members.append(
                _StateSqliteSourceMember(
                    label=label,
                    filename=filename,
                    present=observed is not None,
                    initial=observed,
                )
            )
        if not members[0].present:
            raise UnsafeLocalPath("state SQLite main 缺失")
        if members[1].present != members[2].present:
            raise UnsafeLocalPath("state SQLite WAL/SHM 必须同时存在或同时缺失")
        self._mode = (
            "wal_triplet_read_only" if members[1].present else "main_only_immutable"
        )
        return tuple(members)

    @staticmethod
    def _windows_handle_details(handle: int) -> tuple[int, int, int, int, int, int, int]:
        import ctypes
        from ctypes import wintypes

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = (
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetFileInformationByHandle.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        )
        kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            wintypes.HANDLE(handle), ctypes.byref(information)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)
        mtime_100ns = (
            int(information.ftLastWriteTime.dwHighDateTime) << 32
        ) | int(information.ftLastWriteTime.dwLowDateTime)
        return (
            int(information.dwFileAttributes),
            int(information.nNumberOfLinks),
            size,
            mtime_100ns,
            int(information.dwVolumeSerialNumber),
            int(information.nFileIndexHigh),
            int(information.nFileIndexLow),
        )

    def _open_windows_member(
        self,
        member: _StateSqliteSourceMember,
    ) -> None:
        """CreateFile 返回后先登记 exact handle，再执行任何 fallible probe。"""

        import ctypes
        from ctypes import wintypes

        path = self._path_for(member)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ；机械拒绝既存/新增 writer 与 delete
            None,
            3,  # OPEN_EXISTING
            0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            error = ctypes.get_last_error()
            raise UnsafeLocalPath(
                f"state SQLite source 无法建立 no-share-write/delete guard: {error}"
            )
        member.windows_handle = int(handle)

    def _open_posix_member(self, member: _StateSqliteSourceMember) -> None:
        if not self._persistence._allow_posix_test_only:
            raise UnsafeLocalPath("POSIX state SQLite source 只允许显式 test-only")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = self._parent_guard.open_file(member.filename, flags)
        member.posix_descriptor = descriptor

    def _validate_open_member(self, member: _StateSqliteSourceMember) -> None:
        path = self._path_for(member)
        initial = member.initial
        observed = self._persistence._safe_root.preflight(
            path,
            expected_kind="file",
            allow_absent=False,
        )
        if initial is None or observed is None:
            raise UnsafeLocalPath("state SQLite member 缺打开前身份")
        if os.name == "nt":
            handle = member.windows_handle
            if handle is None:
                raise UnsafeLocalPath("state SQLite member 缺 Windows guard")
            details = self._windows_handle_details(handle)
            attributes, links, size, _mtime, volume, high, low = details
            if (
                _BoundDirectory._windows_final_path(handle) != str(path)
                or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or attributes & 0x10  # FILE_ATTRIBUTE_DIRECTORY
                or links != 1
                or size != observed.st_size
                or not _same_file_identity(initial, observed)
                or _BoundDirectory._windows_kernel_identity(handle)
                != (volume, high, low)
            ):
                raise UnsafeLocalPath("state SQLite Windows open-instance 身份漂移")
            return
        descriptor = member.posix_descriptor
        if descriptor is None:
            raise UnsafeLocalPath("state SQLite member 缺 POSIX descriptor")
        opened = os.fstat(descriptor)
        if (
            not _same_file_identity(initial, opened)
            or not _same_file_identity(opened, observed)
            or not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or getattr(opened, "st_nlink", 1) != 1
        ):
            raise UnsafeLocalPath("state SQLite POSIX open-instance 身份漂移")

    def _acquire(self) -> None:
        self._members = self._preflight_presence()
        for member in self._members:
            if not member.present:
                continue
            if os.name == "nt":
                self._open_windows_member(member)
            else:
                self._open_posix_member(member)
            self._validate_open_member(member)
        # 全部 handle 已登记后重验 absent/present closure。
        self._baseline = self._observe_members()

    @staticmethod
    def _read_windows_handle(handle: int, expected_size: int) -> bytes:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetFilePointerEx.argtypes = (
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        )
        kernel32.SetFilePointerEx.restype = wintypes.BOOL
        if not kernel32.SetFilePointerEx(
            wintypes.HANDLE(handle), 0, None, 0
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel32.ReadFile.argtypes = (
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPDWORD,
            wintypes.LPVOID,
        )
        kernel32.ReadFile.restype = wintypes.BOOL
        result = bytearray()
        while len(result) < expected_size:
            amount = min(1024 * 1024, expected_size - len(result))
            buffer = ctypes.create_string_buffer(amount)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                wintypes.HANDLE(handle), buffer, amount, ctypes.byref(read), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if read.value == 0:
                raise UnsafeLocalPath("state SQLite Windows handle short read")
            result.extend(buffer.raw[: read.value])
        return bytes(result)

    def _observe_present_member(
        self,
        member: _StateSqliteSourceMember,
    ) -> StateSqliteMemberObservation:
        path = self._path_for(member)
        observed = self._persistence._safe_root.preflight(
            path,
            expected_kind="file",
            allow_absent=False,
        )
        if observed is None or member.initial is None:
            raise UnsafeLocalPath("state SQLite pinned member 消失")
        if os.name == "nt":
            handle = member.windows_handle
            if handle is None:
                raise UnsafeLocalPath("state SQLite Windows guard 已丢失")
            before = self._windows_handle_details(handle)
            attributes, links, size, mtime_100ns, volume, high, low = before
            if (
                _BoundDirectory._windows_final_path(handle) != str(path)
                or attributes & (_FILE_ATTRIBUTE_REPARSE_POINT | 0x10)
                or links != 1
                or size != observed.st_size
                or not _same_file_identity(member.initial, observed)
            ):
                raise UnsafeLocalPath("state SQLite Windows member 观察前身份漂移")
            raw = self._read_windows_handle(handle, size)
            after = self._windows_handle_details(handle)
            confirmed = self._persistence._safe_root.preflight(
                path,
                expected_kind="file",
                allow_absent=False,
            )
            if before != after or confirmed is None or not _same_file_identity(
                member.initial, confirmed
            ):
                raise UnsafeLocalPath("state SQLite Windows member 读取期间漂移")
            mtime_ns = (mtime_100ns - 116444736000000000) * 100
            volume_hash = _identity.identity_sha256(
                {"scheme": "windows_volume", "volume_serial": volume}
            )
            file_hash = _identity.identity_sha256(
                {
                    "scheme": "windows_file_id",
                    "volume_serial": volume,
                    "file_index_high": high,
                    "file_index_low": low,
                }
            )
            scheme = "windows_file_id"
        else:
            descriptor = member.posix_descriptor
            if descriptor is None:
                raise UnsafeLocalPath("state SQLite POSIX descriptor 已丢失")
            before_stat = os.fstat(descriptor)
            if (
                not _same_file_identity(member.initial, before_stat)
                or not _same_file_identity(before_stat, observed)
                or getattr(before_stat, "st_nlink", 1) != 1
            ):
                raise UnsafeLocalPath("state SQLite POSIX member 观察前身份漂移")
            os.lseek(descriptor, 0, os.SEEK_SET)
            blocks: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                blocks.append(block)
            raw = b"".join(blocks)
            after_stat = os.fstat(descriptor)
            confirmed = self._persistence._safe_root.preflight(
                path,
                expected_kind="file",
                allow_absent=False,
            )
            if (
                not _same_file_identity(before_stat, after_stat)
                or before_stat.st_size != after_stat.st_size
                or before_stat.st_mtime_ns != after_stat.st_mtime_ns
                or confirmed is None
                or not _same_file_identity(member.initial, confirmed)
            ):
                raise UnsafeLocalPath("state SQLite POSIX member 读取期间漂移")
            size = int(after_stat.st_size)
            mtime_ns = int(after_stat.st_mtime_ns)
            volume_hash = _identity.identity_sha256(
                {"scheme": "posix_test_device", "device": int(after_stat.st_dev)}
            )
            file_hash = _identity.identity_sha256(
                {
                    "scheme": "posix_test_inode",
                    "device": int(after_stat.st_dev),
                    "inode": int(after_stat.st_ino),
                }
            )
            scheme = "posix_test_only"
        if len(raw) != size:
            raise UnsafeLocalPath("state SQLite member bytes 与 handle size 不同")
        return StateSqliteMemberObservation(
            label=member.label,
            presence="present",
            identity_scheme=scheme,
            size=size,
            mtime_ns=mtime_ns,
            bytes_sha256=hashlib.sha256(raw).hexdigest(),
            volume_identity_sha256=volume_hash,
            file_identity_sha256=file_hash,
        )

    def _observe_members(self) -> tuple[StateSqliteMemberObservation, ...]:
        basename = _STATE_SQLITE_DATABASES[self._database]
        journal = self._persistence.layout.state / f"{basename}-journal"
        if self._persistence._safe_root.preflight(
            journal,
            expected_kind="file",
            allow_absent=True,
        ) is not None:
            raise UnsafeLocalPath("state SQLite backup 期间出现 rollback journal")
        observations: list[StateSqliteMemberObservation] = []
        for member in self._members:
            if member.present:
                observations.append(self._observe_present_member(member))
                continue
            if self._persistence._safe_root.preflight(
                self._path_for(member),
                expected_kind="file",
                allow_absent=True,
            ) is not None:
                raise UnsafeLocalPath("state SQLite absent sidecar 出现第三值")
            observations.append(
                StateSqliteMemberObservation(
                    label=member.label,
                    presence="absent",
                    identity_scheme=None,
                    size=None,
                    mtime_ns=None,
                    bytes_sha256=None,
                    volume_identity_sha256=None,
                    file_identity_sha256=None,
                )
            )
        return tuple(observations)

    def _open_source_connection(self) -> sqlite3.Connection:
        path = self._persistence.layout.state / _STATE_SQLITE_DATABASES[self._database]
        uri = "file:" + quote(str(path).replace("\\", "/"), safe="/:" )
        uri += "?mode=ro"
        if self._mode == "main_only_immutable":
            uri += "&immutable=1"
        connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=0)
        self._source_connections.append(connection)
        connection.execute("PRAGMA query_only=ON")
        return connection

    def _close_source_connection(self, connection: sqlite3.Connection) -> None:
        if connection not in self._source_connections:
            return
        connection.close()
        self._source_connections.remove(connection)

    def backup_to_memory(self) -> LockedStateSqliteMemoryView:
        """形成 raw in-memory backup view；不执行 VACUUM 或 B3 语义资格检查。"""

        self._assert_live()
        before = self._observe_members()
        if self._baseline is None or before != self._baseline:
            raise UnsafeLocalPath(
                "state SQLite source 自 acquisition 后发生身份/字节漂移"
            )
        source_connection: sqlite3.Connection | None = None
        view: LockedStateSqliteMemoryView | None = None
        try:
            source_connection = self._open_source_connection()
            memory = sqlite3.connect(":memory:", isolation_level=None)
            view = LockedStateSqliteMemoryView(
                source=self,
                connection=memory,
                _construction_token=_LOCKED_STATE_SQLITE_VIEW_TOKEN,
            )
            self._views.add(view)
            source_connection.backup(memory)
            memory.execute("PRAGMA query_only=ON")
            self._close_source_connection(source_connection)
            source_connection = None
            after = self._observe_members()
            view._activate(before=before, after=after)
            return view
        except BaseException:
            close_error: BaseException | None = None
            if source_connection is not None:
                try:
                    self._close_source_connection(source_connection)
                except BaseException as error:
                    close_error = error
            if view is not None:
                try:
                    view._close_from_source(
                        _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                    )
                except BaseException as error:
                    if close_error is None:
                        close_error = error
            if close_error is not None:
                self._workspace._mark_source_closing()
            raise

    def _close_memory_view_connection(
        self,
        view: LockedStateSqliteMemoryView,
    ) -> None:
        if view not in self._views:
            raise UnsafeLocalPath("state SQLite memory view 不属于 source")
        view._connection.close()
        self._views.remove(view)
        # close 与 tracking/closed 状态在同一 state owner 内单调提交；外层
        # wrapper post-return 异常不得把已闭合 view 重新变成 live authority。
        view._closed = True

    def _close_memory_view_public(self, view: LockedStateSqliteMemoryView) -> None:
        self._assert_live()
        try:
            view._close_from_source(_close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN)
        except BaseException:
            self._workspace._mark_source_closing()
            raise

    def _retire_windows_numeric_authority(self, *, reason: str) -> None:
        for member in self._members:
            member.windows_handle = None
        self._state = "owner_crash_only"
        self._lock._enter_owner_crash_only(reason=reason)

    def _close_windows_member(self, member: _StateSqliteSourceMember) -> None:
        handle = member.windows_handle
        if handle is None:
            return
        try:
            # 复用 Round7 唯一、已审核的 DUPLICATE_CLOSE_SOURCE syscall seam。
            # 文档保证只要调用返回，source handle 即已关闭，不论 BOOL 状态。
            CrashReleasedFileLock._windows_duplicate_close_source_call(handle)
        except BaseException as error:
            self._retire_windows_numeric_authority(
                reason="state_sqlite_source_close_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "state SQLite Windows guard close outcome 不可判定；owner-crash-only"
            ) from error
        member.windows_handle = None

    def _close_posix_member(self, member: _StateSqliteSourceMember) -> None:
        descriptor = member.posix_descriptor
        if descriptor is None:
            return
        if member.posix_close_ambiguous:
            raise LocalDeploymentPersistenceError(
                "POSIX state SQLite source close 结果歧义；test-only 永久 fail-closed"
            )
        try:
            os.close(descriptor)
        except OSError as error:
            if _descriptor_no_longer_exact(descriptor, member.initial):
                member.posix_descriptor = None
                return
            member.posix_close_ambiguous = True
            raise LocalDeploymentPersistenceError(
                "POSIX state SQLite source close 结果歧义"
            ) from error
        member.posix_descriptor = None

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("state SQLite source close authority 不匹配")
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "state SQLite source 只允许 owner 进程退出回收"
            )
        self._state = "closing"
        close_error: BaseException | None = None
        for view in tuple(self._views):
            try:
                view._close_from_source(_close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN)
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for connection in tuple(self._source_connections):
            try:
                self._close_source_connection(connection)
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for member in self._members:
            try:
                if os.name == "nt":
                    self._close_windows_member(member)
                else:
                    self._close_posix_member(member)
            except BaseException as error:
                # outer wrapper 在 state owner 已单调提交后抛错时，成员字段已经
                # 清空；该异常不能反向恢复 numeric authority。
                if (
                    (os.name == "nt" and member.windows_handle is None)
                    and self._state != "owner_crash_only"
                ):
                    continue
                if close_error is None:
                    close_error = error
        if (
            close_error is not None
            or self._views
            or self._source_connections
            or any(
                member.windows_handle is not None
                or member.posix_descriptor is not None
                for member in self._members
            )
        ):
            raise LocalDeploymentPersistenceError(
                "state SQLite source resource 关闭失败"
            ) from close_error
        self._state = "closed"
        self._workspace._release_state_source(self)

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_state_source_public(self)

    def __enter__(self) -> "LockedStateSqliteSource":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


def _production_state_member_document(
    observation: StateSqliteMemberObservation,
) -> dict[str, object] | None:
    """Return the closed, re-observable portion of one pinned state member."""

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
        raise UnsafeLocalPath("production state member observation 不闭合")
    return {
        "identity_scheme": observation.identity_scheme,
        "bytes": observation.size,
        "mtime_ns": observation.mtime_ns,
        "bytes_sha256": observation.bytes_sha256,
        "volume_identity_sha256": observation.volume_identity_sha256,
        "file_identity_sha256": observation.file_identity_sha256,
    }


def _locked_production_state_order_sha256(
    sources: Mapping[str, LockedStateSqliteSource],
    *,
    persistence: "LocalDeploymentPersistence",
    workspace: "LockedAttemptWorkspace",
) -> str:
    """Rebuild the ordered production-state seal from live source pins.

    The projection deliberately contains only material that a fresh B2 replay
    can observe again.  Deployment nonces and transient authorizations remain
    separately bound by the aggregate and journal and therefore cannot make a
    durable state fingerprint impossible to re-observe after a controller
    crash.
    """

    if type(sources) is not dict or tuple(sources) != tuple(
        _STATE_SQLITE_DATABASES
    ):
        raise UnsafeLocalPath("production state source 集合/顺序不闭合")
    rows: list[dict[str, object]] = []
    for database in _STATE_SQLITE_DATABASES:
        source = sources[database]
        if (
            type(source) is not LockedStateSqliteSource
            or source._persistence is not persistence
            or source._workspace is not workspace
            or source._database != database
            or source._state != "live"
        ):
            raise UnsafeLocalPath(
                "production state source 不属于同一 B2 workspace"
            )
        source.checkpoint_unchanged()
        observed = source._observe_members()
        if source._baseline is None or observed != source._baseline:
            raise UnsafeLocalPath("production state source checkpoint 漂移")
        members: list[dict[str, object]] = []
        for member, member_observation in zip(
            source._members, observed, strict=True
        ):
            if member.label != member_observation.label:
                raise UnsafeLocalPath("production state member 顺序漂移")
            members.append(
                {
                    "role": member.label,
                    "canonical_path": str(source._path_for(member)),
                    "presence": member_observation.presence,
                    "observation": _production_state_member_document(
                        member_observation
                    ),
                }
            )
        rows.append({"database_name": database, "members": members})
    return _identity.identity_sha256(rows)


@dataclass(slots=True)
class _ExactReleasePinnedMember:
    role: str
    relative_path: str
    expected_size: int
    expected_sha256: str
    initial: os.stat_result | None = None
    windows_handle: int | None = None
    posix_descriptor: int | None = None
    posix_close_ambiguous: bool = False
    raw: bytes | None = None


@dataclass(slots=True)
class _ExactReleaseRoleState:
    role: str
    reference: Mapping[str, object]
    directory: Path
    entry: ReleaseInventoryEntry | None = None
    manifest: Mapping[str, object] | None = None
    manifest_raw: bytes | None = None
    members: tuple[_ExactReleasePinnedMember, ...] = ()
    migration_paths: tuple[str, ...] = ()
    namespace_monitor: object | None = None


class LockedBootstrapCommentSchemaExpandAuthorization:
    """同一 B2 lock epoch 内、仅对 durable bootstrap root-preflight 有效的能力。

    该对象不携带路径，也不允许调用者自报 attempt/nonce/state。每次使用都会重放
    journal 并重新确认它仍是唯一 active 的 ``root_preflight_verified`` revision、
    workspace 仍属于同一 lock epoch，且 active/prior control 仍然为空。
    """

    __slots__ = (
        "_persistence",
        "_workspace",
        "_acquisition_epoch",
        "_journal_sha256",
        "_state_identity_sha256",
        "_candidate_ref_raw",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError(
            "bootstrap comment schema expand authorization 不允许派生伪 capability"
        )

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        workspace: "LockedAttemptWorkspace",
        acquisition_epoch: _LockAcquisitionEpoch,
        journal_sha256: str,
        state_identity_sha256: str,
        candidate_reference: Mapping[str, object],
        _construction_token: object,
    ):
        if (
            _construction_token
            is not _LOCKED_BOOTSTRAP_COMMENT_SCHEMA_EXPAND_AUTHORIZATION_TOKEN
        ):
            raise DeploymentLockBusy(
                "bootstrap comment schema expand authorization 必须由 persistence façade 构造"
            )
        self._persistence = persistence
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._journal_sha256 = journal_sha256
        self._state_identity_sha256 = state_identity_sha256
        self._candidate_ref_raw = _identity.canonical_bytes(
            _release_ref(
                candidate_reference,
                label="bootstrap comment schema expand candidate",
            )
        )

    def __reduce__(self) -> object:
        raise TypeError(
            "bootstrap comment schema expand authorization is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> Mapping[str, object]:
        if (
            type(self._persistence) is not LocalDeploymentPersistence
            or type(self._workspace) is not LockedAttemptWorkspace
        ):
            raise DeploymentLockBusy(
                "bootstrap comment schema expand authorization 类型漂移"
            )
        self._workspace._assert_live()
        if (
            self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "bootstrap comment schema expand authorization authority/epoch 漂移"
            )
        history = self._persistence.journals.replay(self._workspace.attempt_id)
        latest = history[-1]
        active = self._persistence.journals.active_revisions()
        evidence = latest["evidence_hashes"]
        if (
            len(active) != 1
            or active[0] != latest
            or latest["attempt"] != self._workspace.attempt_id
            or latest["nonce"] != self._workspace.nonce
            or latest["operation"] != "bootstrap_first_pair"
            or latest["phase"] != "root_preflight_verified"
            or latest["journal_sha256"] != self._journal_sha256
            or latest["original_pair"] is not None
            or latest["database_seals"] != []
            or latest["transient_start"] != []
            or latest["state_plan"]["database_names"]
            != ["comments", "research_workspace"]
            or latest["state_plan"]["state_identity_sha256"]
            != self._state_identity_sha256
            or not isinstance(evidence, Mapping)
            or evidence.get("root_preflight_sha256") is None
            or _identity.canonical_bytes(
                _release_ref(
                    latest["candidate"],
                    label="latest bootstrap comment schema expand candidate",
                )
            )
            != self._candidate_ref_raw
        ):
            raise DeploymentJournalError(
                "bootstrap comment schema expand authorization 已被 durable journal 撤销"
            )
        if (
            self._persistence.read_active_release() is not None
            or self._persistence.read_local_prior_binding() is not None
        ):
            raise DeploymentJournalError(
                "bootstrap comment schema expand authorization 要求 absent active/prior control"
            )
        return latest

    @property
    def scope(self) -> str:
        self._assert_live()
        return _BOOTSTRAP_COMMENT_SCHEMA_EXPAND_AUTHORIZATION_SCOPE


class LockedExactTransientStartAuthorization:
    """由 latest durable journal 派生的瞬态启动输入能力。

    该对象不启动服务、不持有 writer lease，也不形成任何运行资格。它只在同一
    ``CrashReleasedFileLock`` acquisition epoch 与 live attempt workspace 内有效；
    每次读取 property 都会重放 latest journal，确认 phase、record、material hash
    和 journal hash 未变化。对象没有 document/as_dict 或任意路径读取接口。
    """

    __slots__ = (
        "_persistence",
        "_workspace",
        "_acquisition_epoch",
        "_journal_sha256",
        "_operation",
        "_phase",
        "_role",
        "_start_nonce",
        "_scm_identity_sha256",
        "_state_identity_sha256",
        "_authorization_sha256",
        "_release_ref_raw",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError(
            "exact transient start authorization 不允许派生伪 capability"
        )

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        workspace: "LockedAttemptWorkspace",
        acquisition_epoch: _LockAcquisitionEpoch,
        journal_sha256: str,
        operation: str,
        phase: str,
        role: str,
        start_nonce: str,
        scm_identity_sha256: str,
        state_identity_sha256: str,
        authorization_sha256: str,
        release_reference: Mapping[str, object],
        _construction_token: object,
    ):
        if (
            _construction_token
            is not _LOCKED_EXACT_TRANSIENT_START_AUTHORIZATION_TOKEN
        ):
            raise DeploymentLockBusy(
                "exact transient start authorization 必须由 persistence façade 构造"
            )
        self._persistence = persistence
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._journal_sha256 = journal_sha256
        self._operation = operation
        self._phase = phase
        self._role = role
        self._start_nonce = start_nonce
        self._scm_identity_sha256 = scm_identity_sha256
        self._state_identity_sha256 = state_identity_sha256
        self._authorization_sha256 = authorization_sha256
        validated_reference = _release_ref(
            release_reference,
            label="exact transient start release",
        )
        self._release_ref_raw = _identity.canonical_bytes(validated_reference)

    def __reduce__(self) -> object:
        raise TypeError(
            "exact transient start authorization is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @staticmethod
    def _select_start(
        latest: Mapping[str, object], role: str
    ) -> Mapping[str, object]:
        starts = latest["transient_start"]
        if not isinstance(starts, list):
            raise DeploymentJournalError("latest journal transient_start 类型漂移")
        matches = [
            item
            for item in starts
            if isinstance(item, Mapping) and item.get("role") == role
        ]
        if len(matches) != 1:
            raise DeploymentJournalError(
                "latest journal 没有该 role 的唯一 transient start authorization"
            )
        return matches[0]

    def _assert_live(self) -> Mapping[str, object]:
        self._workspace._assert_live()
        if (
            self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "exact transient start authorization authority/epoch 漂移"
            )
        history = self._persistence.journals.replay(self._workspace.attempt_id)
        latest = history[-1]
        _assert_transient_authorization_phase_open(latest)
        if (
            latest["attempt"] != self._workspace.attempt_id
            or latest["nonce"] != self._workspace.nonce
            or latest["journal_sha256"] != self._journal_sha256
            or latest["operation"] != self._operation
            or latest["phase"] != self._phase
        ):
            raise DeploymentJournalError(
                "exact transient start authorization 已因 latest journal 漂移而撤销"
            )
        start = self._select_start(latest, self._role)
        authorization_sha256 = _transient_start_authorization_sha256(
            latest, start
        )
        evidence_field = _transient_start_authorization_evidence_field(
            self._role
        )
        evidence = latest["evidence_hashes"]
        if not isinstance(evidence, Mapping):
            raise DeploymentJournalError("latest journal evidence_hashes 类型漂移")
        release_raw = _identity.canonical_bytes(
            _release_ref(start["release"], label="latest transient start release")
        )
        if (
            authorization_sha256 != self._authorization_sha256
            or evidence.get(evidence_field) != authorization_sha256
            or start["start_nonce"] != self._start_nonce
            or start["scm_identity_sha256"] != self._scm_identity_sha256
            or latest["state_plan"]["state_identity_sha256"]
            != self._state_identity_sha256
            or release_raw != self._release_ref_raw
        ):
            raise DeploymentJournalError(
                "exact transient start authorization record/material 已漂移"
            )
        return start

    @property
    def scope(self) -> str:
        self._assert_live()
        return _EXACT_TRANSIENT_START_AUTHORIZATION_SCOPE

    @property
    def operation(self) -> str:
        self._assert_live()
        return self._operation

    @property
    def phase(self) -> str:
        self._assert_live()
        return self._phase

    @property
    def attempt_id(self) -> str:
        self._assert_live()
        return self._workspace.attempt_id

    @property
    def nonce(self) -> str:
        self._assert_live()
        return self._workspace.nonce

    @property
    def role(self) -> str:
        self._assert_live()
        return self._role

    @property
    def start_nonce(self) -> str:
        self._assert_live()
        return self._start_nonce

    @property
    def scm_identity_sha256(self) -> str:
        self._assert_live()
        return self._scm_identity_sha256

    @property
    def state_identity_sha256(self) -> str:
        self._assert_live()
        return self._state_identity_sha256

    @property
    def authorization_sha256(self) -> str:
        self._assert_live()
        return self._authorization_sha256

    @property
    def release_ref(self) -> Mapping[str, object]:
        self._assert_live()
        cloned = json.loads(self._release_ref_raw.decode("utf-8"))
        if not isinstance(cloned, dict):
            raise DeploymentJournalError(
                "exact transient start release clone 类型漂移"
            )
        return cloned


class LockedVerifiedPhaseCasAuthorization:
    """Narrow process-local authority derived only from a durable verified phase.

    It cannot rebuild canary or qualification.  Every property replays the exact
    verified revision and rechecks the retained release closure/compatibility,
    current active pointer/prior binding, and pinned production state.
    """

    __slots__ = (
        "_persistence",
        "_workspace",
        "_acquisition_epoch",
        "_journal_sha256",
        "_phase",
        "_role",
        "_qualification_sha256",
        "_active_raw",
        "_binding_raw",
        "_next_action",
        "_state_sources",
        "_production_state_order_sha256",
        "_closures",
        "_release_compatibility_sha256",
        "_release_closure_sha256",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("verified-phase CAS authorization 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError(
                "verified-phase CAS authorization 构造后不可替换"
            )
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        workspace: "LockedAttemptWorkspace",
        acquisition_epoch: _LockAcquisitionEpoch,
        journal_sha256: str,
        phase: str,
        role: str,
        qualification_sha256: str,
        active_raw: bytes | None,
        binding_raw: bytes | None,
        next_action: str,
        state_sources: Mapping[str, LockedStateSqliteSource],
        production_state_order_sha256: str,
        closures: "LockedExactReleaseClosures",
        release_compatibility_sha256: str,
        release_closure_sha256: str,
        _construction_token: object,
    ):
        if (
            _construction_token
            is not _LOCKED_VERIFIED_PHASE_CAS_AUTHORIZATION_TOKEN
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization 必须由 B2 consume seam 构造"
            )
        object.__setattr__(self, "_sealed", False)
        self._persistence = persistence
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._journal_sha256 = journal_sha256
        self._phase = phase
        self._role = role
        self._qualification_sha256 = qualification_sha256
        self._active_raw = None if active_raw is None else bytes(active_raw)
        self._binding_raw = None if binding_raw is None else bytes(binding_raw)
        self._next_action = next_action
        if type(state_sources) is not dict or tuple(state_sources) != tuple(
            _STATE_SQLITE_DATABASES
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization 缺少 ordered live state sources"
            )
        self._state_sources = tuple(
            state_sources[database] for database in _STATE_SQLITE_DATABASES
        )
        if not _SHA256_RE.fullmatch(production_state_order_sha256):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization state seal 不闭合"
            )
        self._production_state_order_sha256 = production_state_order_sha256
        if (
            type(closures) is not LockedExactReleaseClosures
            or closures._persistence is not persistence
            or closures._workspace is not workspace
            or closures._lock is not workspace._lock
            or closures._state != "live"
            or not _SHA256_RE.fullmatch(release_compatibility_sha256)
            or not _SHA256_RE.fullmatch(release_closure_sha256)
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization exact release closure 不闭合"
            )
        self._closures = closures
        self._release_compatibility_sha256 = release_compatibility_sha256
        self._release_closure_sha256 = release_closure_sha256
        self._state = "live"
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("verified-phase CAS authorization is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> Mapping[str, object]:
        from .local_exact_release_compatibility import (
            build_exact_release_compatibility_evidence,
        )

        if self._state != "live":
            raise DeploymentLockBusy(
                "verified-phase CAS authorization 已消费或退休"
            )
        self._workspace._assert_live()
        if (
            self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization authority/epoch 漂移"
            )
        if (
            type(self._closures) is not LockedExactReleaseClosures
            or self._closures._persistence is not self._persistence
            or self._closures._workspace is not self._workspace
            or self._closures._lock is not self._workspace._lock
            or self._closures._state != "live"
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization release closure 已失效"
            )
        self._closures.checkpoint_unchanged()
        closure_metadata = self._closures.metadata()
        compatibility = build_exact_release_compatibility_evidence(
            self._closures
        )
        if (
            _identity.identity_sha256(closure_metadata)
            != self._release_closure_sha256
            or compatibility.aggregate_sha256
            != self._release_compatibility_sha256
        ):
            raise DeploymentJournalError(
                "verified-phase CAS authorization release closure/compatibility 漂移"
            )
        history = self._persistence.journals.replay(self._workspace.attempt_id)
        latest = history[-1]
        evidence_field = (
            "prior_runtime_qualification_sha256"
            if self._role == "prior"
            else "candidate_runtime_qualification_sha256"
        )
        if (
            latest["attempt"] != self._workspace.attempt_id
            or latest["nonce"] != self._workspace.nonce
            or latest["journal_sha256"] != self._journal_sha256
            or latest["phase"] != self._phase
            or latest["evidence_hashes"].get(evidence_field)
            != self._qualification_sha256
        ):
            raise DeploymentJournalError(
                "verified-phase CAS authorization 已因 journal 漂移而撤销"
            )
        active = self._persistence.read_active_release()
        binding = self._persistence.read_local_prior_binding()
        active_raw = None if active is None else active.raw
        binding_raw = None if binding is None else binding.raw
        if active_raw != self._active_raw or binding_raw != self._binding_raw:
            raise CompareAndSwapConflict(
                "verified-phase CAS authorization pointer/binding 漂移"
            )
        if (
            _locked_production_state_order_sha256(
                dict(zip(_STATE_SQLITE_DATABASES, self._state_sources, strict=True)),
                persistence=self._persistence,
                workspace=self._workspace,
            )
            != self._production_state_order_sha256
        ):
            raise CompareAndSwapConflict(
                "verified-phase CAS authorization production state 漂移"
            )
        # 夹住 metadata/compatibility/journal/pointer/state 全部复验窗口；新的
        # recursive monitor 已在旧 monitor 关闭前启动，期间任一 namespace ABA
        # 会在这里单调撤销 authorization。
        self._closures.checkpoint_unchanged()
        return latest

    def _assert_post_cas_live(
        self,
        expected_latest: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Recheck every non-CAS owner after the desired record is durable."""

        from .local_exact_release_compatibility import (
            build_exact_release_compatibility_evidence,
        )

        if self._state != "live":
            raise DeploymentLockBusy(
                "verified-phase CAS authorization 已消费或退休"
            )
        self._workspace._assert_live()
        if (
            self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
            or type(self._closures) is not LockedExactReleaseClosures
            or self._closures._persistence is not self._persistence
            or self._closures._workspace is not self._workspace
            or self._closures._lock is not self._workspace._lock
            or self._closures._state != "live"
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization post-CAS owner/closure 漂移"
            )
        self._closures.checkpoint_unchanged()
        closure_metadata = self._closures.metadata()
        compatibility = build_exact_release_compatibility_evidence(
            self._closures
        )
        if (
            _identity.identity_sha256(closure_metadata)
            != self._release_closure_sha256
            or compatibility.aggregate_sha256
            != self._release_compatibility_sha256
        ):
            raise DeploymentJournalError(
                "verified-phase CAS authorization post-CAS release 漂移"
            )
        latest = self._persistence.journals.replay(
            self._workspace.attempt_id
        )[-1]
        if latest != expected_latest:
            raise DeploymentJournalError(
                "verified-phase CAS authorization post-CAS journal 漂移"
            )
        if (
            _locked_production_state_order_sha256(
                dict(
                    zip(
                        _STATE_SQLITE_DATABASES,
                        self._state_sources,
                        strict=True,
                    )
                ),
                persistence=self._persistence,
                workspace=self._workspace,
            )
            != self._production_state_order_sha256
        ):
            raise CompareAndSwapConflict(
                "verified-phase CAS authorization post-CAS production state 漂移"
            )
        self._closures.checkpoint_unchanged()
        return latest

    def _mark_consumed_from_b2(
        self,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: "LockedAttemptWorkspace",
        journal_sha256: str,
    ) -> None:
        if (
            self._state != "live"
            or persistence is not self._persistence
            or workspace is not self._workspace
            or workspace._lock is not lock
            or journal_sha256 != self._journal_sha256
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS authorization consume authority 不闭合"
            )
        object.__setattr__(self, "_state", "consumed")

    def _retire_owner_crash_only(
        self,
        *,
        reason: str,
    ) -> None:
        object.__setattr__(self, "_state", "owner_crash_only")
        self._workspace._lock._enter_owner_crash_only(reason=reason)

    def _mirror_release_closure_retirement(self) -> None:
        closure_state = getattr(self._closures, "_state", None)
        if closure_state == "owner_crash_only":
            object.__setattr__(self, "_state", "owner_crash_only")
        elif closure_state == "revoked":
            object.__setattr__(self, "_state", "revoked")

    @property
    def scope(self) -> str:
        self._assert_live()
        return "verified_phase_next_cas_authorization"

    @property
    def phase(self) -> str:
        self._assert_live()
        return self._phase

    @property
    def role(self) -> str:
        self._assert_live()
        return self._role

    @property
    def next_action(self) -> str:
        self._assert_live()
        return self._next_action

    @property
    def qualification_sha256(self) -> str:
        self._assert_live()
        return self._qualification_sha256


class LockedExactReleaseClosures:
    """同一 lock epoch 内由 durable journal 唯一派生的 release closure 输入。

    它固定 release manifest 与 manifest inventory 的每个 file open instance；其中六个
    research_workspace migration 另提供固定枚举读取，并在入场和出场执行完整 closure
    扫描。该对象只是后续 B3 验证的输入能力，不是 compatibility、SCM、writer-lease
    或部署资格证明。
    """

    __slots__ = (
        "_persistence",
        "_workspace",
        "_lock",
        "_operation",
        "_state_identity_sha256",
        "_planned_compatibility_sha256",
        "_roles",
        "_state",
    )

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: "LockedAttemptWorkspace",
        operation: str,
        state_identity_sha256: str,
        planned_compatibility_sha256: str,
        role_references: Sequence[tuple[str, Mapping[str, object]]],
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_EXACT_RELEASE_CLOSURES_TOKEN:
            raise UnsafeLocalPath(
                "exact release closures 必须由 persistence façade 构造"
            )
        self._persistence = persistence
        self._workspace = workspace
        self._lock = lock
        self._operation = operation
        self._state_identity_sha256 = state_identity_sha256
        self._planned_compatibility_sha256 = planned_compatibility_sha256
        self._roles = tuple(
            _ExactReleaseRoleState(
                role=role,
                reference=reference,
                directory=(
                    persistence.layout.releases / str(reference["release_id"])
                ),
            )
            for role, reference in role_references
        )
        self._state = "acquiring"

    def __reduce__(self) -> object:
        raise TypeError(
            "exact release closures is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        return "exact_release_closure_input_only"

    @property
    def operation(self) -> str:
        self._assert_live()
        return self._operation

    @property
    def attempt_id(self) -> str:
        self._assert_live()
        return self._workspace.attempt_id

    @property
    def nonce(self) -> str:
        self._assert_live()
        return self._workspace.nonce

    @property
    def state_identity_sha256(self) -> str:
        self._assert_live()
        return self._state_identity_sha256

    @property
    def planned_compatibility_sha256(self) -> str:
        """返回 journal revision 0 预先密封的 compatibility aggregate。"""

        self._assert_live()
        return self._planned_compatibility_sha256

    @property
    def roles(self) -> tuple[str, ...]:
        self._assert_live()
        return tuple(role.role for role in self._roles)

    @staticmethod
    def _clone_json(value: object) -> object:
        return json.loads(_identity.canonical_bytes(value).decode("utf-8"))

    def metadata(self) -> Mapping[str, object]:
        """返回不含产品绝对路径与 raw handle 的可变隔离 clone。"""

        self._assert_live()
        role_metadata: dict[str, object] = {"prior": None}
        for role in self._roles:
            if role.entry is None or role.manifest is None:
                raise UnsafeLocalPath("exact release role 尚未闭合")
            role_metadata[role.role] = {
                "release_id": role.entry.release_id,
                "manifest_sha256": role.entry.manifest_sha256,
                "inventory_sha256": role.entry.closure_sha256,
                "sealed_core_sha256": _identity.sealed_release_core_sha256(
                    role.manifest
                ),
                "migrations": [
                    {
                        "relative_path": logical_path,
                        "bytes": member.expected_size,
                        "sha256": member.expected_sha256,
                    }
                    for logical_path, physical_path in zip(
                        _EXACT_RELEASE_MIGRATIONS,
                        role.migration_paths,
                        strict=True,
                    )
                    for member in role.members
                    if member.relative_path == physical_path
                ],
            }
        value = {
            "scope": self.scope,
            "operation": self._operation,
            "attempt_id": self._workspace.attempt_id,
            "nonce": self._workspace.nonce,
            "state_identity_sha256": self._state_identity_sha256,
            "planned_compatibility_sha256": self._planned_compatibility_sha256,
            "roles": role_metadata,
        }
        cloned = self._clone_json(value)
        if not isinstance(cloned, dict):
            raise UnsafeLocalPath("exact release metadata clone 类型漂移")
        return cloned

    def _role(self, role: str) -> _ExactReleaseRoleState:
        if role not in {"candidate", "prior"}:
            raise UnsafeLocalPath("release role 只允许 candidate/prior")
        for current in self._roles:
            if current.role == role:
                return current
        raise UnsafeLocalPath("bootstrap exact release closures 没有 prior")

    def read_manifest(self, role: str) -> Mapping[str, object]:
        self._assert_live()
        current = self._role(role)
        if current.manifest is None:
            raise UnsafeLocalPath("exact release manifest 尚未闭合")
        cloned = self._clone_json(current.manifest)
        if not isinstance(cloned, dict):
            raise UnsafeLocalPath("exact release manifest clone 类型漂移")
        return cloned

    def read_migration(self, role: str, migration: str) -> bytes:
        self._assert_live()
        if type(migration) is not str or migration not in _EXACT_RELEASE_MIGRATIONS:
            raise UnsafeLocalPath("migration 只允许固定 research_workspace 枚举")
        current = self._role(role)
        physical_migration = current.migration_paths[
            _EXACT_RELEASE_MIGRATIONS.index(migration)
        ]
        for member in current.members:
            if member.relative_path == physical_migration:
                if member.raw is None:
                    raise UnsafeLocalPath("migration bytes 尚未闭合")
                return bytes(member.raw)
        raise UnsafeLocalPath("migration 不属于 exact release role")

    def _assert_live(self) -> None:
        if self._state != "live":
            raise UnsafeLocalPath("exact release closures 不再处于 live 状态")
        self._workspace._assert_live()

    @staticmethod
    def _new_namespace_monitor(directory: Path) -> object:
        # 局部导入保持 B2 persistence 不在模块加载时反向依赖 tooling scanner。
        # 该 monitor 在 Windows 使用递归 overlapped ReadDirectoryChangesW；POSIX
        # 只属于 test-only，仍由每次完整 rescan 检测当前第三成员。
        from .local_exact_runtime_tooling_scanner import (
            _WindowsNamespaceChangeMonitor,
        )

        return _WindowsNamespaceChangeMonitor(directory)

    @staticmethod
    def _known_namespace_change(error: BaseException) -> bool:
        return isinstance(
            error,
            (
                RetentionPlanningError,
                UnsafeLocalPath,
                _identity.LocalReleaseIdentityError,
            ),
        ) or "namespace changed during claim construction" in str(error)

    @staticmethod
    def _close_namespace_monitor(monitor: object | None) -> BaseException | None:
        if monitor is None:
            return None
        try:
            monitor.close()  # type: ignore[attr-defined]
        except BaseException as error:
            return error
        return None

    def _retire_namespace_authority(
        self,
        *,
        errors: Sequence[BaseException],
        reason: str,
    ) -> None:
        ambiguous = any(
            not self._known_namespace_change(error) for error in errors
        )
        if ambiguous:
            self._state = "owner_crash_only"
            self._lock._enter_owner_crash_only(reason=reason)
        else:
            self._state = "revoked"

    def checkpoint_unchanged(self) -> None:
        """复验完整 release tree，并无空窗轮换递归 namespace monitors。"""

        self._assert_live()
        self._checkpoint_namespace_unchanged()

    def _checkpoint_namespace_unchanged(self) -> None:
        """State-owner core；workspace closing 路径已由 close token 授权。"""

        old_monitors = tuple(role.namespace_monitor for role in self._roles)
        replacements: list[object] = []
        checkpoint_error: BaseException | None = None
        try:
            # replacement 全部先于 rescan 启动；旧 monitor 在 rescan 完成后才取消，
            # 因此 add→delete ABA 不能藏在相邻 checkpoint 的切换空窗中。
            for role in self._roles:
                replacements.append(
                    self._new_namespace_monitor(role.directory)
                )
            self._verify_all()
        except BaseException as error:
            checkpoint_error = error

        close_errors: list[BaseException] = []
        for monitor in old_monitors:
            error = self._close_namespace_monitor(monitor)
            if error is not None:
                close_errors.append(error)

        if checkpoint_error is None and not close_errors:
            for role, replacement in zip(
                self._roles, replacements, strict=True
            ):
                role.namespace_monitor = replacement
            return

        # 本轮失败后任何 replacement 都不能继续成为 authority。即使 rescan
        # 观察到的当前树已恢复，旧 monitor 的通知仍会把 ABA 单调撤销。
        for replacement in replacements:
            error = self._close_namespace_monitor(replacement)
            if error is not None:
                close_errors.append(error)
        for role in self._roles:
            role.namespace_monitor = None
        errors = tuple(
            error
            for error in (checkpoint_error, *close_errors)
            if error is not None
        )
        self._retire_namespace_authority(
            errors=errors,
            reason="exact_release_namespace_checkpoint_outcome_unknown",
        )
        if self._state == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "exact release namespace checkpoint 结果不明；owner-crash-only"
            ) from errors[0]
        raise RetentionPlanningError(
            "exact release namespace 自上次 checkpoint 后发生漂移"
        ) from errors[0]

    def _path_for(
        self,
        role: _ExactReleaseRoleState,
        member: _ExactReleasePinnedMember,
    ) -> Path:
        return role.directory.joinpath(*member.relative_path.split("/"))

    @staticmethod
    def _migration_layout(release: Mapping[str, object]) -> tuple[str, ...]:
        prefixes = (
            "migrations/research_workspace/",
            "runtime_contract/migrations/research_workspace/",
        )
        observed = {
            str(item["path"])
            for item in release["inventory"]["files"]
            if str(item["path"]).startswith(prefixes)
        }
        matches = [
            layout
            for layout in _EXACT_RELEASE_MIGRATION_LAYOUTS
            if observed == set(layout)
        ]
        if len(matches) != 1:
            raise RetentionPlanningError(
                "research_workspace migration subtree 必须恰为固定六文件"
            )
        return matches[0]

    def _open_windows_member(
        self,
        role: _ExactReleaseRoleState,
        member: _ExactReleasePinnedMember,
    ) -> None:
        import ctypes
        from ctypes import wintypes

        path = self._path_for(role, member)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ，拒绝 write/delete/rename
            None,
            3,
            0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            raise UnsafeLocalPath(
                "exact release member 无法建立 no-share-write/delete guard: "
                f"{ctypes.get_last_error()}"
            )
        # CreateFile 一旦返回便立即登记；后续 probe 异常不会遗失 resource。
        member.windows_handle = int(handle)

    def _open_posix_member(
        self,
        role: _ExactReleaseRoleState,
        member: _ExactReleasePinnedMember,
        parent_guard: _BoundDirectory,
    ) -> None:
        del role
        if not self._persistence._allow_posix_test_only:
            raise UnsafeLocalPath("POSIX exact release pin 只允许 test-only")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        member.posix_descriptor = parent_guard.open_file(
            member.relative_path.rsplit("/", 1)[-1], flags
        )

    def _read_member(
        self,
        role: _ExactReleaseRoleState,
        member: _ExactReleasePinnedMember,
    ) -> bytes:
        path = self._path_for(role, member)
        initial = member.initial
        observed = self._persistence._safe_root.preflight(
            path, expected_kind="file", allow_absent=False
        )
        if initial is None or observed is None:
            raise RetentionPlanningError("exact release member 缺初始身份")
        if os.name == "nt":
            handle = member.windows_handle
            if handle is None:
                raise RetentionPlanningError("exact release member 缺 Windows guard")
            details = LockedStateSqliteSource._windows_handle_details(handle)
            attributes, links, size, _mtime, volume, high, low = details
            if (
                _BoundDirectory._windows_final_path(handle) != str(path)
                or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or attributes & 0x10
                or links != 1
                or size != observed.st_size
                or not _same_file_identity(initial, observed)
                or _BoundDirectory._windows_kernel_identity(handle)
                != (volume, high, low)
            ):
                raise RetentionPlanningError(
                    "exact release Windows open-instance 身份漂移"
                )
            raw = LockedStateSqliteSource._read_windows_handle(handle, size)
        else:
            descriptor = member.posix_descriptor
            if descriptor is None:
                raise RetentionPlanningError("exact release member 缺 POSIX descriptor")
            opened = os.fstat(descriptor)
            if (
                not _same_file_identity(initial, opened)
                or not _same_file_identity(opened, observed)
                or not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or getattr(opened, "st_nlink", 1) != 1
            ):
                raise RetentionPlanningError(
                    "exact release POSIX open-instance 身份漂移"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            blocks: list[bytes] = []
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                blocks.append(block)
            raw = b"".join(blocks)
        if (
            len(raw) != member.expected_size
            or hashlib.sha256(raw).hexdigest() != member.expected_sha256
        ):
            raise RetentionPlanningError("exact release pinned bytes/hash 漂移")
        return raw

    def _scan_role(
        self, role: _ExactReleaseRoleState
    ) -> tuple[ReleaseInventoryEntry, Mapping[str, object], tuple[str, ...]]:
        entry, release = self._persistence._scan_release(role.directory)
        reference = role.reference
        if (
            entry.release_id != reference["release_id"]
            or entry.manifest_sha256 != reference["manifest_sha256"]
        ):
            raise RetentionPlanningError(
                "journal release ref 未解析到 exact manifest ID/hash"
            )
        migration_paths = self._migration_layout(release)
        return entry, release, migration_paths

    def _acquire_role(self, role: _ExactReleaseRoleState) -> None:
        lock = self._lock
        epoch = self._workspace._acquisition_epoch
        lock._shared_directory_guard(
            role.directory,
            authority_token=self._persistence._authority_token,
            acquisition_epoch=epoch,
        )
        # 必须先启动递归 monitor，再做第一次 manifest/inventory 枚举。
        role.namespace_monitor = self._new_namespace_monitor(role.directory)
        entry, release, migration_paths = self._scan_role(role)
        manifest_raw = _identity.canonical_bytes(release)
        members: list[_ExactReleasePinnedMember] = [
            _ExactReleasePinnedMember(
                role=role.role,
                relative_path="release_manifest.json",
                expected_size=len(manifest_raw),
                expected_sha256=entry.manifest_sha256,
            )
        ]
        for record in release["inventory"]["files"]:
            relative = str(record["path"])
            members.append(
                _ExactReleasePinnedMember(
                    role=role.role,
                    relative_path=relative,
                    expected_size=int(record["bytes"]),
                    expected_sha256=str(record["sha256"]),
                )
            )
        role.entry = entry
        role.manifest = release
        role.manifest_raw = manifest_raw
        role.members = tuple(members)
        role.migration_paths = migration_paths
        for member in role.members:
            path = self._path_for(role, member)
            initial = self._persistence._safe_root.preflight(
                path, expected_kind="file", allow_absent=False
            )
            if initial is None or getattr(initial, "st_nlink", 1) != 1:
                raise RetentionPlanningError(
                    "exact release member 不是普通 single-link file"
                )
            member.initial = initial
            parent_guard = lock._shared_directory_guard(
                path.parent,
                authority_token=self._persistence._authority_token,
                acquisition_epoch=epoch,
            )
            if os.name == "nt":
                self._open_windows_member(role, member)
            else:
                self._open_posix_member(role, member, parent_guard)
            raw = self._read_member(role, member)
            if (
                member.relative_path == "release_manifest.json"
                or member.relative_path in role.migration_paths
            ):
                member.raw = raw
        confirmed_entry, confirmed_release, confirmed_migration_paths = (
            self._scan_role(role)
        )
        if (
            confirmed_entry != entry
            or confirmed_release != release
            or confirmed_migration_paths != migration_paths
        ):
            raise RetentionPlanningError(
                "exact release closure 在 open-instance acquisition 期间漂移"
            )

    def _acquire(self) -> None:
        lock = self._lock
        lock._shared_directory_guard(
            self._persistence.layout.releases,
            authority_token=self._persistence._authority_token,
            acquisition_epoch=self._workspace._acquisition_epoch,
        )
        for role in self._roles:
            self._acquire_role(role)
        if len(self._roles) == 2:
            candidate, prior = self._roles
            if candidate.role != "candidate" or prior.role != "prior":
                raise RetentionPlanningError("exact release role ordering 漂移")
            if (
                candidate.entry is None
                or prior.entry is None
                or candidate.manifest is None
                or prior.manifest is None
                or candidate.entry.release_id == prior.entry.release_id
                or candidate.entry.manifest_sha256 == prior.entry.manifest_sha256
                or _identity.sealed_release_core_sha256(candidate.manifest)
                == _identity.sealed_release_core_sha256(prior.manifest)
            ):
                raise RetentionPlanningError(
                    "candidate/prior 必须是 genuinely distinct sealed cores"
                )
        self._state = "live"

    def _verify_all(self) -> None:
        for role in self._roles:
            if role.entry is None or role.manifest is None:
                raise RetentionPlanningError("exact release role 未完成 acquisition")
            entry, release, migration_paths = self._scan_role(role)
            if (
                entry != role.entry
                or release != role.manifest
                or migration_paths != role.migration_paths
            ):
                raise RetentionPlanningError("exact release full closure 出场漂移")
            for member in role.members:
                # 上一次可判定 close fault 可能已经单调闭合了部分成员；full
                # closure scan 已重新证明这些路径的 bytes/hash，重试时只对仍由
                # 本对象持有的 open instance 做 handle 复核。unknown close 不会
                # 进入这里，因为它已经把整个能力退休为 owner_crash_only。
                if (
                    os.name == "nt"
                    and member.windows_handle is None
                ) or (
                    os.name != "nt"
                    and member.posix_descriptor is None
                ):
                    continue
                raw = self._read_member(role, member)
                if (
                    member.relative_path == "release_manifest.json"
                    or member.relative_path in role.migration_paths
                ) and (member.raw is None or raw != member.raw):
                    raise RetentionPlanningError(
                        "exact release pinned member 出场 bytes 漂移"
                    )

    def _retire_windows_numeric_authority(self, *, reason: str) -> None:
        for role in self._roles:
            for member in role.members:
                member.windows_handle = None
        self._state = "owner_crash_only"
        self._lock._enter_owner_crash_only(reason=reason)

    def _close_windows_member(self, member: _ExactReleasePinnedMember) -> None:
        handle = member.windows_handle
        if handle is None:
            return
        try:
            CrashReleasedFileLock._windows_duplicate_close_source_call(handle)
        except BaseException as error:
            self._retire_windows_numeric_authority(
                reason="exact_release_closure_close_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "exact release Windows guard close outcome 不可判定；owner-crash-only"
            ) from error
        member.windows_handle = None

    def _close_posix_member(self, member: _ExactReleasePinnedMember) -> None:
        descriptor = member.posix_descriptor
        if descriptor is None:
            return
        if member.posix_close_ambiguous:
            raise LocalDeploymentPersistenceError(
                "POSIX exact release close 结果歧义；test-only 永久 fail-closed"
            )
        try:
            os.close(descriptor)
        except OSError as error:
            if _descriptor_no_longer_exact(descriptor, member.initial):
                member.posix_descriptor = None
                return
            member.posix_close_ambiguous = True
            raise LocalDeploymentPersistenceError(
                "POSIX exact release close 结果歧义"
            ) from error
        member.posix_descriptor = None

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("exact release closures close authority 不匹配")
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "exact release closures 只允许 owner 进程退出回收"
            )
        acquiring = self._state == "acquiring"
        revoked = self._state == "revoked"
        if not acquiring and not revoked:
            self._checkpoint_namespace_unchanged()
        self._state = "closing"
        # 已成功入场后，最后一个 overlapping namespace checkpoint 在关闭任何
        # file handle 前完成；revoked authority 重试 cleanup 时不恢复或重扫资格。
        namespace_errors: list[BaseException] = []
        for role in self._roles:
            monitor = role.namespace_monitor
            role.namespace_monitor = None
            error = self._close_namespace_monitor(monitor)
            if error is not None:
                namespace_errors.append(error)
        if namespace_errors and any(
            not self._known_namespace_change(error)
            for error in namespace_errors
        ):
            self._state = "owner_crash_only"
            self._lock._enter_owner_crash_only(
                reason="exact_release_namespace_close_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "exact release namespace close 结果不明；owner-crash-only"
            ) from namespace_errors[0]
        close_error: BaseException | None = None
        for role in self._roles:
            for member in role.members:
                try:
                    if os.name == "nt":
                        self._close_windows_member(member)
                    else:
                        self._close_posix_member(member)
                except BaseException as error:
                    if (
                        os.name == "nt"
                        and member.windows_handle is None
                        and self._state != "owner_crash_only"
                    ):
                        continue
                    if close_error is None:
                        close_error = error
        if close_error is not None or any(
            member.windows_handle is not None
            or member.posix_descriptor is not None
            for role in self._roles
            for member in role.members
        ):
            raise LocalDeploymentPersistenceError(
                "exact release closures resource 关闭失败"
            ) from close_error
        self._state = "closed"
        self._workspace._release_exact_release_closures(self)
        if namespace_errors:
            raise RetentionPlanningError(
                "exact release namespace 在 closure close 前发生漂移"
            ) from namespace_errors[0]

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_exact_release_closures_public(self)

    def __enter__(self) -> "LockedExactReleaseClosures":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedExactScmProcessObservationInput:
    """把 exact start authorization 与 live release closure 闭合为观察输入。

    本对象不查询 SCM、不打开进程、不持有 writer lease，也不形成资格。它只把
    后续 Windows observer 的固定计划绑定到同一 B2 lock/workspace/epoch。
    """

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_acquisition_epoch",
        "_authorization",
        "_closures",
        "_closure_role",
        "_plan_raw",
        "_plan_sha256",
        "_release_ref_raw",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("exact SCM/process observation input 不允许派生")

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: "LockedAttemptWorkspace",
        acquisition_epoch: _LockAcquisitionEpoch,
        authorization: LockedExactTransientStartAuthorization,
        closures: LockedExactReleaseClosures,
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_EXACT_SCM_PROCESS_OBSERVATION_INPUT_TOKEN:
            raise DeploymentLockBusy(
                "exact SCM/process observation input 必须由 persistence façade 构造"
            )
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._authorization = authorization
        self._closures = closures
        self._closure_role = ""
        self._plan_raw = b""
        self._plan_sha256 = ""
        self._release_ref_raw = b""
        plan, closure_role, release_ref = self._derive_live_material()
        self._closure_role = closure_role
        self._plan_raw = _identity.canonical_bytes(plan)
        self._plan_sha256 = _identity.identity_sha256(plan)
        self._release_ref_raw = _identity.canonical_bytes(release_ref)

    def __reduce__(self) -> object:
        raise TypeError(
            "exact SCM/process observation input is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _derive_live_material(
        self,
    ) -> tuple[Mapping[str, object], str, Mapping[str, object]]:
        self._workspace._assert_live()
        if (
            self._workspace._lock is not self._lock
            or self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "exact SCM/process observation input authority/epoch 漂移"
            )
        if (
            type(self._authorization) is not LockedExactTransientStartAuthorization
            or type(self._closures) is not LockedExactReleaseClosures
            or self._authorization._persistence is not self._persistence
            or self._authorization._workspace is not self._workspace
            or self._authorization._acquisition_epoch is not self._acquisition_epoch
            or self._closures._persistence is not self._persistence
            or self._closures._workspace is not self._workspace
            or self._closures._lock is not self._lock
        ):
            raise DeploymentLockBusy(
                "exact SCM/process observation input 必须闭合同一 exact capabilities"
            )
        start = self._authorization._assert_live()
        self._closures._assert_live()
        operation = self._authorization._operation
        role = self._authorization._role
        if operation == "activation":
            role_map = {"prior": "prior", "candidate": "candidate"}
        elif operation == "rollback":
            role_map = {"prior": "candidate", "candidate": "candidate"}
        elif operation == "bootstrap_first_pair":
            role_map = {"baseline": "candidate"}
        else:
            raise DeploymentJournalError("SCM/process observation operation 不支持")
        closure_role = role_map.get(role)
        if closure_role is None:
            raise DeploymentJournalError(
                "SCM/process observation role 与 operation 不相容"
            )
        if (
            self._closures._operation != operation
            or self._closures._workspace.attempt_id
            != self._authorization._workspace.attempt_id
            or self._closures._workspace.nonce
            != self._authorization._workspace.nonce
            or self._closures._state_identity_sha256
            != self._authorization._state_identity_sha256
        ):
            raise DeploymentJournalError(
                "SCM/process observation authorization/closure 身份不一致"
            )
        metadata = self._closures.metadata()
        roles = metadata.get("roles")
        closure_release = (
            roles.get(closure_role) if isinstance(roles, Mapping) else None
        )
        release_ref = _release_ref(
            start["release"], label="SCM/process observation authorized release"
        )
        if (
            not isinstance(closure_release, Mapping)
            or closure_release.get("release_id") != release_ref["release_id"]
            or closure_release.get("manifest_sha256")
            != release_ref["manifest_sha256"]
        ):
            raise DeploymentJournalError(
                "SCM/process observation authorized release 不属于 exact closure"
            )
        journal_material = {
            "attempt": self._authorization._workspace.attempt_id,
            "nonce": self._authorization._workspace.nonce,
            "operation": operation,
            "state_plan": {
                "state_identity_sha256": self._authorization._state_identity_sha256
            },
        }
        plan = _transient_scm_start_plan_material(journal_material, start)
        plan_sha256 = _identity.identity_sha256(plan)
        if plan_sha256 != self._authorization._scm_identity_sha256:
            raise DeploymentJournalError(
                "SCM/process observation start plan 未绑定 authorization"
            )
        return plan, closure_role, release_ref

    def _assert_live(self) -> Mapping[str, object]:
        plan, closure_role, release_ref = self._derive_live_material()
        if (
            closure_role != self._closure_role
            or _identity.canonical_bytes(plan) != self._plan_raw
            or _identity.identity_sha256(plan) != self._plan_sha256
            or _identity.canonical_bytes(release_ref) != self._release_ref_raw
        ):
            raise DeploymentJournalError(
                "exact SCM/process observation input material 已漂移"
            )
        return plan

    @property
    def scope(self) -> str:
        self._assert_live()
        return _EXACT_SCM_PROCESS_OBSERVATION_INPUT_SCOPE

    @property
    def attempt_id(self) -> str:
        plan = self._assert_live()
        return str(plan["attempt"])

    @property
    def nonce(self) -> str:
        plan = self._assert_live()
        return str(plan["nonce"])

    @property
    def operation(self) -> str:
        plan = self._assert_live()
        return str(plan["operation"])

    @property
    def role(self) -> str:
        plan = self._assert_live()
        return str(plan["role"])

    @property
    def start_nonce(self) -> str:
        plan = self._assert_live()
        return str(plan["start_nonce"])

    @property
    def state_identity_sha256(self) -> str:
        plan = self._assert_live()
        return str(plan["state_identity_sha256"])

    @property
    def authorization_sha256(self) -> str:
        self._assert_live()
        return self._authorization._authorization_sha256

    @property
    def scm_identity_sha256(self) -> str:
        self._assert_live()
        return self._plan_sha256

    @property
    def closure_role(self) -> str:
        self._assert_live()
        return self._closure_role

    @property
    def release_ref(self) -> Mapping[str, object]:
        self._assert_live()
        cloned = json.loads(self._release_ref_raw.decode("utf-8"))
        if not isinstance(cloned, dict):
            raise DeploymentJournalError("SCM/process release clone 类型漂移")
        return cloned

    @property
    def service_name(self) -> str:
        plan = self._assert_live()
        return str(plan["service"]["service_name"])

    @property
    def service_executable(self) -> str:
        plan = self._assert_live()
        return str(plan["service"]["binary_path"])

    @property
    def python_class(self) -> str:
        plan = self._assert_live()
        return str(plan["service"]["python_class"])

    @property
    def child_executable(self) -> str:
        plan = self._assert_live()
        return str(plan["child"]["executable"])

    @property
    def child_argv(self) -> tuple[str, ...]:
        plan = self._assert_live()
        return tuple(str(value) for value in plan["child"]["argv"])

    @property
    def service_start_arguments(self) -> tuple[str, ...]:
        plan = self._assert_live()
        return tuple(
            str(value) for value in plan["service"]["start_arguments"]
        )


@dataclass(slots=True)
class _TrackedWindowsHandleSlot:
    label: str
    family: str
    phase: str = "prepared"
    value: int | None = None


_WINDOWS_SCM_PROCESS_HANDLE_SLOT_FAMILIES = (
    ("scm_manager", "scm"),
    ("scm_service", "scm"),
    ("python_class_registry", "registry"),
    ("host_process", "kernel"),
    ("host_executable", "kernel"),
    ("snapshot_before", "kernel"),
    ("child_process", "kernel"),
    ("child_executable", "kernel"),
    ("snapshot_after", "kernel"),
)

_WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS = frozenset(
    {"snapshot_before", "snapshot_after"}
)


class _WindowsScmProcessHandleTrackingCore:
    """同一 B2 workspace 下的固定 Windows handle 生命周期输入。

    本对象只负责在任何 observer syscall 前进入 workspace tracking，并以固定
    slot 管理返回 handle。它不查询 SCM、不解释进程、不生成 evidence，也不
    形成 writer lease 或 qualification。所有 raw handle 接口均为模块内部接缝。
    """

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_acquisition_epoch",
        "_inputs",
        "_tracking_kind",
        "_slots",
        "_state",
        "_retirement_sha256",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: object,
        acquisition_epoch: _LockAcquisitionEpoch,
        inputs: object,
        tracking_kind: str,
        _construction_token: object,
    ):
        valid_token = (
            tracking_kind == "transient"
            and _construction_token
            is _LOCKED_WINDOWS_SCM_PROCESS_HANDLE_TRACKING_TOKEN
        ) or (
            tracking_kind == "steady"
            and _construction_token
            is _LOCKED_WINDOWS_STEADY_SCM_PROCESS_HANDLE_TRACKING_TOKEN
        )
        if not valid_token:
            raise DeploymentLockBusy(
                "Windows SCM/process handle tracking 必须由 B2 façade 构造"
            )
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._inputs = inputs
        self._tracking_kind = tracking_kind
        self._slots = tuple(
            _TrackedWindowsHandleSlot(label, family)
            for label, family in _WINDOWS_SCM_PROCESS_HANDLE_SLOT_FAMILIES
        )
        self._state = "acquiring"
        self._retirement_sha256: str | None = None

    def __reduce__(self) -> object:
        raise TypeError(
            "Windows SCM/process handle tracking is process-local and "
            "non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_context(self, *, states: set[str]) -> None:
        if self._state not in states:
            raise UnsafeLocalPath(
                "Windows SCM/process handle tracking 状态不允许该操作"
            )
        self._workspace._assert_live()  # type: ignore[attr-defined]
        from .local_steady_start_authorization import (
            LockedExactSteadyScmProcessObservationInput,
        )

        exact_pair = (
            self._tracking_kind == "transient"
            and type(self) is LockedWindowsScmProcessHandleTracking
            and type(self._workspace) is LockedAttemptWorkspace
            and type(self._inputs) is LockedExactScmProcessObservationInput
        ) or (
            self._tracking_kind == "steady"
            and type(self) is LockedWindowsSteadyScmProcessHandleTracking
            and type(self._workspace) is LockedSteadyBootWorkspace
            and type(self._inputs)
            is LockedExactSteadyScmProcessObservationInput
        )
        if (
            self._workspace._lock is not self._lock
            or self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
            or not exact_pair
        ):
            raise DeploymentLockBusy(
                "Windows SCM/process handle tracking authority/epoch 漂移"
            )
        if self._tracking_kind == "steady":
            self._inputs._assert_process_local_live()  # type: ignore[attr-defined]
        else:
            self._inputs._assert_live()  # type: ignore[attr-defined]

    def _slot(self, label: str, family: str | None = None) -> _TrackedWindowsHandleSlot:
        if type(label) is not str or (
            family is not None and type(family) is not str
        ):
            raise UnsafeLocalPath("Windows handle slot label/family 类型无效")
        matches = [slot for slot in self._slots if slot.label == label]
        if len(matches) != 1:
            raise UnsafeLocalPath("Windows handle slot 不属于固定枚举")
        slot = matches[0]
        if family is not None and slot.family != family:
            raise UnsafeLocalPath("Windows handle slot family 不匹配")
        return slot

    def _retire_numeric_authority(self, *, reason: str) -> None:
        occupied = [slot.label for slot in self._slots if slot.value is not None]
        if self._tracking_kind == "transient":
            identity: dict[str, object] = {
                "authority_kind": "transient_attempt",
                "attempt_id": self._workspace.attempt_id,
                "nonce": self._workspace.nonce,
            }
        elif self._tracking_kind == "steady":
            identity = {
                "authority_kind": "steady_active",
                "boot_nonce": self._workspace.boot_nonce,
            }
        else:
            raise DeploymentLockBusy("Windows handle tracking kind 漂移")
        self._retirement_sha256 = _identity.identity_sha256(
            {
                "scope": "windows_handle_numeric_authority_retired",
                **identity,
                "reason": reason,
                "occupied_slots": occupied,
            }
        )
        for slot in self._slots:
            slot.value = None
            slot.phase = "retired"
        self._state = "owner_crash_only"
        self._lock._enter_owner_crash_only(reason=reason)

    def _capture_returned_handle(
        self,
        label: str,
        family: str,
        function: Callable[..., object],
        *arguments: object,
    ) -> None:
        """内部 state-owner syscall seam；不向 caller 返回 raw handle。"""

        self._capture_returned_handle_for_states(
            label,
            family,
            function,
            arguments,
            states={"acquiring"},
            prepared_phases={"prepared"},
        )

    def _capture_returned_handle_for_states(
        self,
        label: str,
        family: str,
        function: Callable[..., object],
        arguments: tuple[object, ...],
        *,
        states: set[str],
        prepared_phases: set[str],
    ) -> None:
        if (
            states == {"acquiring"}
            and prepared_phases == {"prepared"}
        ):
            pass
        elif (
            states == {"acquiring", "live"}
            and prepared_phases == {"prepared", "reusable_prepared"}
            and label in _WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS
            and family == "kernel"
        ):
            pass
        else:
            raise UnsafeLocalPath(
                "Windows handle state-owner capture mode 不属于固定枚举"
            )
        self._assert_context(states=states)
        if not callable(function):
            raise UnsafeLocalPath("Windows handle syscall 必须可调用")
        import ctypes

        pointer_width_invalid = ctypes.c_void_p(-1).value
        if type(pointer_width_invalid) is not int:
            raise UnsafeLocalPath(
                "当前解释器无法机械计算 Windows INVALID_HANDLE_VALUE"
            )
        slot = self._slot(label, family)
        if slot.phase not in prepared_phases or slot.value is not None:
            raise UnsafeLocalPath("Windows handle slot 不得重复取得")
        slot.phase = "syscall_in_progress"
        try:
            # 返回后第一项 state-owner 动作为 slot assignment；不先 int、记录或校验。
            slot.value = function(*arguments)  # type: ignore[assignment]
            slot.phase = "returned"
        except BaseException as error:
            self._retire_numeric_authority(
                reason=f"{label}_syscall_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "Windows handle syscall 结果不可判定；owner-crash-only"
            ) from error
        if slot.value is None:
            slot.value = None
            slot.phase = "failed_without_handle"
            raise LocalDeploymentPersistenceError(
                f"Windows handle syscall 未返回有效 {label}"
            )
        if type(slot.value) is not int:
            self._retire_numeric_authority(
                reason=f"{label}_returned_handle_type_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "Windows handle syscall 返回类型不可安全关闭；owner-crash-only"
            )
        if slot.value in {0, -1, pointer_width_invalid}:
            slot.value = None
            slot.phase = "failed_without_handle"
            raise LocalDeploymentPersistenceError(
                f"Windows handle syscall 未返回有效 {label}"
            )
        if slot.value > pointer_width_invalid:
            self._retire_numeric_authority(
                reason=f"{label}_returned_handle_out_of_pointer_range"
            )
            raise LocalDeploymentPersistenceError(
                "Windows handle syscall 返回值超出当前 HANDLE 整数域；"
                "owner-crash-only"
            )
        if slot.value < 1:
            self._retire_numeric_authority(
                reason=f"{label}_returned_handle_value_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "Windows handle syscall 返回值不可安全关闭；owner-crash-only"
            )

    def _capture_reusable_snapshot_handle(
        self,
        label: str,
        function: Callable[..., object],
        *arguments: object,
    ) -> None:
        """取得一次性 Toolhelp snapshot，允许 acquisition/live 阶段重复轮换。"""

        if label not in _WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS:
            raise UnsafeLocalPath("reusable snapshot slot 不属于固定枚举")
        slot = self._slot(label, "kernel")
        try:
            self._capture_returned_handle_for_states(
                label,
                "kernel",
                function,
                arguments,
                states={"acquiring", "live"},
                prepared_phases={"prepared", "reusable_prepared"},
            )
        except BaseException:
            if (
                self._state in {"acquiring", "live"}
                and slot.value is None
                and slot.phase == "failed_without_handle"
            ):
                slot.phase = "reusable_prepared"
            raise

    def _release_reusable_snapshot_handle(self, label: str) -> None:
        """机械关闭一次性 snapshot；只有确定关闭后才允许同槽再次取得。"""

        self._assert_context(states={"acquiring", "live"})
        if label not in _WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS:
            raise UnsafeLocalPath("reusable snapshot slot 不属于固定枚举")
        slot = self._slot(label, "kernel")
        if slot.phase != "returned" or type(slot.value) is not int:
            raise UnsafeLocalPath("reusable snapshot slot 不含 live handle")
        self._close_slot(slot)
        if self._state == "owner_crash_only" or slot.value is not None:
            raise LocalDeploymentPersistenceError(
                "reusable snapshot handle 未机械闭合"
            )
        slot.phase = "reusable_prepared"

    def _borrow_handle(self, label: str, family: str) -> int:
        self._assert_context(states={"acquiring", "live"})
        slot = self._slot(label, family)
        if slot.phase != "returned" or type(slot.value) is not int:
            raise UnsafeLocalPath("Windows handle slot 尚未取得 live handle")
        return slot.value

    def _capture_registry_output_handle(
        self,
        label: str,
        function: Callable[..., object],
        *arguments: object,
    ) -> None:
        """提交 RegOpenKeyExW out handle，即使 wrapper 随后抛错也不遗失。"""

        import ctypes
        from ctypes import wintypes

        self._assert_context(states={"acquiring"})
        if not callable(function):
            raise UnsafeLocalPath("registry output syscall 必须可调用")
        slot = self._slot(label, "registry")
        if slot.phase != "prepared" or slot.value is not None:
            raise UnsafeLocalPath("registry output slot 不得重复取得")
        output = wintypes.HANDLE()
        status: object | None = None
        call_error: BaseException | None = None
        slot.phase = "syscall_in_progress"
        try:
            status = function(*arguments, ctypes.byref(output))
        except BaseException as error:
            call_error = error
        finally:
            # out parameter 一旦非空，先在 state owner 中提交，再传播任何异常。
            if output.value is not None:
                slot.value = output.value
                slot.phase = "returned"
        if call_error is not None:
            if slot.value is None:
                self._retire_numeric_authority(
                    reason=f"{label}_output_syscall_outcome_unknown"
                )
                raise LocalDeploymentPersistenceError(
                    "registry output syscall 结果不可判定；owner-crash-only"
                ) from call_error
            if type(slot.value) is not int or slot.value < 1:
                self._retire_numeric_authority(
                    reason=f"{label}_output_handle_type_unknown"
                )
                raise LocalDeploymentPersistenceError(
                    "registry output handle 类型不可判定；owner-crash-only"
                ) from call_error
            raise LocalDeploymentPersistenceError(
                "registry output handle 已登记；caller 必须执行 tracking cleanup"
            ) from call_error
        if type(status) is not int:
            self._retire_numeric_authority(
                reason=f"{label}_output_status_type_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "registry output status 类型不可判定；owner-crash-only"
            )
        if status != 0:
            if slot.value is not None:
                self._retire_numeric_authority(
                    reason=f"{label}_failure_with_output_handle_unknown"
                )
                raise LocalDeploymentPersistenceError(
                    "registry failure 同时返回 output；owner-crash-only"
                )
            slot.phase = "failed_without_handle"
            raise LocalDeploymentPersistenceError(
                "registry output syscall 未返回有效 handle"
            )
        if type(slot.value) is not int or slot.value < 1:
            self._retire_numeric_authority(
                reason=f"{label}_success_without_output_handle_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "registry success 缺 output handle；owner-crash-only"
            )

    def _seal_acquisition(self) -> None:
        self._assert_context(states={"acquiring"})
        if any(
            (
                slot.label in _WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS
                and (
                    slot.phase != "reusable_prepared"
                    or slot.value is not None
                )
            )
            or (
                slot.label not in _WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS
                and (slot.phase != "returned" or type(slot.value) is not int)
            )
            for slot in self._slots
        ):
            raise UnsafeLocalPath("Windows handle acquisition slots 尚未全部闭合")
        self._state = "live"

    @staticmethod
    def _windows_close_scm_handle_call(handle: int) -> None:
        if os.name != "nt":
            raise OSError("CloseServiceHandle 只允许 Windows 产品语义")
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.CloseServiceHandle.argtypes = (wintypes.HANDLE,)
        advapi32.CloseServiceHandle.restype = wintypes.BOOL
        if not advapi32.CloseServiceHandle(handle):
            error = ctypes.get_last_error()
            raise OSError(error, f"CloseServiceHandle failed for {handle}")

    @staticmethod
    def _windows_close_registry_handle_call(handle: int) -> None:
        if os.name != "nt":
            raise OSError("RegCloseKey 只允许 Windows 产品语义")
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.RegCloseKey.argtypes = (wintypes.HANDLE,)
        advapi32.RegCloseKey.restype = wintypes.LONG
        status = int(advapi32.RegCloseKey(handle))
        if status != 0:
            raise OSError(status, f"RegCloseKey failed for {handle}")

    def _close_slot_owned(self, slot: _TrackedWindowsHandleSlot) -> None:
        handle = slot.value
        if handle is None:
            return
        if type(handle) is not int or handle < 1:
            self._retire_numeric_authority(
                reason=f"{slot.label}_close_numeric_authority_invalid"
            )
            raise LocalDeploymentPersistenceError(
                "Windows handle close 缺 exact numeric authority"
            )
        if slot.family == "kernel":
            CrashReleasedFileLock._windows_duplicate_close_source_call(handle)
        elif slot.family == "scm":
            self._windows_close_scm_handle_call(handle)
        elif slot.family == "registry":
            self._windows_close_registry_handle_call(handle)
        else:
            self._retire_numeric_authority(
                reason=f"{slot.label}_close_family_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "Windows handle close family 不可判定"
            )
        # close syscall 已返回后在同一 state owner 内单调提交。
        slot.value = None
        slot.phase = "closed"

    def _close_slot(self, slot: _TrackedWindowsHandleSlot) -> None:
        if slot.value is None:
            return
        try:
            self._close_slot_owned(slot)
        except BaseException as error:
            # outer wrapper 若在 state-owner 已提交后才抛错，不得复活旧数值。
            if slot.value is None and self._state != "owner_crash_only":
                return
            if self._state != "owner_crash_only":
                self._retire_numeric_authority(
                    reason=f"{slot.label}_close_outcome_unknown"
                )
            raise LocalDeploymentPersistenceError(
                "Windows handle close outcome 不可判定；owner-crash-only"
            ) from error

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath(
                "Windows SCM/process handle tracking close authority 不匹配"
            )
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "Windows SCM/process handle 只允许 owner 进程退出回收"
            )
        self._state = "closing"
        close_error: BaseException | None = None
        for slot in reversed(self._slots):
            try:
                self._close_slot(slot)
            except BaseException as error:
                if close_error is None:
                    close_error = error
                if self._state == "owner_crash_only":
                    break
        if (
            close_error is not None
            or self._state == "owner_crash_only"
            or any(slot.value is not None for slot in self._slots)
        ):
            raise LocalDeploymentPersistenceError(
                "Windows SCM/process handle tracking resource 关闭失败"
            ) from close_error
        self._state = "closed"
        self._workspace._release_windows_scm_process_handle_tracking(self)

    @property
    def scope(self) -> str:
        self._assert_context(states={"live"})
        if self._tracking_kind == "transient":
            return _WINDOWS_SCM_PROCESS_HANDLE_TRACKING_SCOPE
        if self._tracking_kind == "steady":
            return _WINDOWS_STEADY_SCM_PROCESS_HANDLE_TRACKING_SCOPE
        raise DeploymentLockBusy("Windows handle tracking kind 漂移")

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_windows_scm_process_handle_tracking_public(self)

    def __enter__(self) -> "_WindowsScmProcessHandleTrackingCore":
        self._assert_context(states={"live"})
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedWindowsScmProcessHandleTracking(
    _WindowsScmProcessHandleTrackingCore
):
    """Transient attempt 专属 Windows SCM/process handle owner。"""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("transient Windows SCM/process tracking 不允许派生")


class LockedWindowsSteadyScmProcessHandleTracking(
    _WindowsScmProcessHandleTrackingCore
):
    """Steady boot 专属 Windows SCM/process handle owner。"""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady Windows SCM/process tracking 不允许派生")


_WINDOWS_WRITER_LEASE_HANDLE_SLOT_LABELS = (
    "lease_record_before",
    "duplicated_writer_lock",
    "unexpected_conflict_handle",
    "lease_record_after",
)


class _WindowsWriterLeaseHandleTrackingCore:
    """同一 B2 workspace 下 writer-lease observer 的固定 kernel HANDLE owner。

    四个 slot 都可按一次 observation 的固定顺序轮换；raw HANDLE 只在模块内部
    state-owner seam 中出现。对象不读租约、不调用 endpoint，也不形成 writer 或
    canary 资格。
    """

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_acquisition_epoch",
        "_scm_tracking",
        "_tracking_kind",
        "_slots",
        "_state",
        "_retirement_sha256",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: object,
        acquisition_epoch: _LockAcquisitionEpoch,
        scm_tracking: object,
        tracking_kind: str,
        _construction_token: object,
    ):
        valid_token = (
            tracking_kind == "transient"
            and _construction_token
            is _LOCKED_WINDOWS_WRITER_LEASE_HANDLE_TRACKING_TOKEN
        ) or (
            tracking_kind == "steady"
            and _construction_token
            is _LOCKED_WINDOWS_STEADY_WRITER_LEASE_HANDLE_TRACKING_TOKEN
        )
        if not valid_token:
            raise DeploymentLockBusy(
                "Windows writer lease tracking 必须由 B2 façade 构造"
            )
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._scm_tracking = scm_tracking
        self._tracking_kind = tracking_kind
        self._slots = tuple(
            _TrackedWindowsHandleSlot(label, "kernel", "reusable_prepared")
            for label in _WINDOWS_WRITER_LEASE_HANDLE_SLOT_LABELS
        )
        self._state = "live"
        self._retirement_sha256: str | None = None

    def __reduce__(self) -> object:
        raise TypeError(
            "Windows writer lease handle tracking is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_context(self) -> None:
        if self._state != "live":
            raise UnsafeLocalPath(
                "Windows writer lease handle tracking 不再 live"
            )
        self._workspace._assert_live()  # type: ignore[attr-defined]
        exact_pair = (
            self._tracking_kind == "transient"
            and type(self) is LockedWindowsWriterLeaseHandleTracking
            and type(self._workspace) is LockedAttemptWorkspace
            and type(self._scm_tracking)
            is LockedWindowsScmProcessHandleTracking
        ) or (
            self._tracking_kind == "steady"
            and type(self) is LockedWindowsSteadyWriterLeaseHandleTracking
            and type(self._workspace) is LockedSteadyBootWorkspace
            and type(self._scm_tracking)
            is LockedWindowsSteadyScmProcessHandleTracking
        )
        if (
            self._workspace._lock is not self._lock
            or self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
            or not exact_pair
            or self._scm_tracking._workspace is not self._workspace
            or self._scm_tracking._lock is not self._lock
            or self._scm_tracking._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "Windows writer lease tracking authority/epoch 漂移"
            )
        self._scm_tracking._assert_context(states={"live"})

    def _slot(self, label: str) -> _TrackedWindowsHandleSlot:
        if type(label) is not str:
            raise UnsafeLocalPath("writer lease handle slot label 类型无效")
        matches = [slot for slot in self._slots if slot.label == label]
        if len(matches) != 1:
            raise UnsafeLocalPath("writer lease handle slot 不属于固定枚举")
        return matches[0]

    def _retire_numeric_authority(self, *, reason: str) -> None:
        occupied = [slot.label for slot in self._slots if slot.value is not None]
        if self._tracking_kind == "transient":
            identity: dict[str, object] = {
                "authority_kind": "transient_attempt",
                "attempt_id": self._workspace.attempt_id,
                "nonce": self._workspace.nonce,
            }
        elif self._tracking_kind == "steady":
            identity = {
                "authority_kind": "steady_active",
                "boot_nonce": self._workspace.boot_nonce,
            }
        else:
            raise DeploymentLockBusy("writer lease tracking kind 漂移")
        self._retirement_sha256 = _identity.identity_sha256(
            {
                "scope": "windows_writer_lease_numeric_authority_retired",
                **identity,
                "reason": reason,
                "occupied_slots": occupied,
            }
        )
        for slot in self._slots:
            slot.value = None
            slot.phase = "retired"
        self._state = "owner_crash_only"
        self._lock._enter_owner_crash_only(reason=reason)

    @staticmethod
    def _pointer_invalid() -> int:
        import ctypes

        invalid = ctypes.c_void_p(-1).value
        if type(invalid) is not int:
            raise UnsafeLocalPath("无法计算 Windows INVALID_HANDLE_VALUE")
        return invalid

    def _commit_returned_value(
        self,
        slot: _TrackedWindowsHandleSlot,
        value: object,
        *,
        failure_is_reusable: bool,
    ) -> bool:
        invalid = self._pointer_invalid()
        slot.value = value  # type: ignore[assignment]
        slot.phase = "returned"
        if slot.value is None:
            slot.value = None
            slot.phase = (
                "reusable_prepared" if failure_is_reusable else "failed_without_handle"
            )
            return False
        if type(slot.value) is not int:
            self._retire_numeric_authority(
                reason=f"{slot.label}_returned_handle_type_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "writer lease handle 返回类型不可安全关闭；owner-crash-only"
            )
        if slot.value in {0, -1, invalid}:
            slot.value = None
            slot.phase = (
                "reusable_prepared" if failure_is_reusable else "failed_without_handle"
            )
            return False
        if slot.value < 1 or slot.value >= invalid:
            self._retire_numeric_authority(
                reason=f"{slot.label}_returned_handle_out_of_pointer_range"
            )
            raise LocalDeploymentPersistenceError(
                "writer lease handle 超出 exact HANDLE 域；owner-crash-only"
            )
        return True

    def _capture_reusable_returned_handle(
        self,
        label: str,
        function: Callable[..., object],
        *arguments: object,
    ) -> None:
        self._assert_context()
        if label not in {
            "lease_record_before",
            "lease_record_after",
        } or not callable(function):
            raise UnsafeLocalPath("writer lease reusable open seam 无效")
        slot = self._slot(label)
        if slot.phase != "reusable_prepared" or slot.value is not None:
            raise UnsafeLocalPath("writer lease reusable slot 不可重复取得")
        slot.phase = "syscall_in_progress"
        try:
            returned = function(*arguments)
            acquired = self._commit_returned_value(
                slot, returned, failure_is_reusable=False
            )
        except BaseException as error:
            if self._state != "owner_crash_only":
                self._retire_numeric_authority(
                    reason=f"{label}_syscall_outcome_unknown"
                )
            raise LocalDeploymentPersistenceError(
                "writer lease open syscall outcome unknown；owner-crash-only"
            ) from error
        if not acquired:
            slot.phase = "reusable_prepared"
            raise LocalDeploymentPersistenceError(
                f"writer lease {label} 未返回有效 handle"
            )

    def _capture_reusable_duplicate_handle(
        self,
        function: Callable[..., object],
        source_process: int,
        source_handle: int,
        target_process: int,
        desired_access: int,
        inherit_handle: bool,
        options: int,
    ) -> None:
        """提交 DuplicateHandle out-param；任何 output 都先进入 state owner。"""

        self._assert_context()
        if (
            not callable(function)
            or any(
                type(value) is not int or value < 1
                for value in (source_process, source_handle, target_process)
            )
            or type(desired_access) is not int
            or type(inherit_handle) is not bool
            or type(options) is not int
        ):
            raise UnsafeLocalPath("DuplicateHandle fixed seam 参数无效")
        slot = self._slot("duplicated_writer_lock")
        if slot.phase != "reusable_prepared" or slot.value is not None:
            raise UnsafeLocalPath("duplicated writer lock slot 不可重复取得")
        import ctypes
        from ctypes import wintypes

        output = wintypes.HANDLE()
        result: object | None = None
        call_error: BaseException | None = None
        slot.phase = "syscall_in_progress"
        try:
            result = function(
                source_process,
                source_handle,
                target_process,
                ctypes.byref(output),
                desired_access,
                inherit_handle,
                options,
            )
        except BaseException as error:
            call_error = error
        finally:
            if output.value is not None:
                self._commit_returned_value(
                    slot, output.value, failure_is_reusable=False
                )
        if call_error is not None:
            if slot.value is None:
                self._retire_numeric_authority(
                    reason="duplicated_writer_lock_output_unknown"
                )
                raise LocalDeploymentPersistenceError(
                    "DuplicateHandle outcome unknown；owner-crash-only"
                ) from call_error
            raise LocalDeploymentPersistenceError(
                "DuplicateHandle output 已登记；caller 必须 cleanup"
            ) from call_error
        if type(result) is not int:
            self._retire_numeric_authority(
                reason="duplicated_writer_lock_result_type_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "DuplicateHandle result 类型无效；owner-crash-only"
            )
        if result == 0:
            if slot.value is not None:
                self._retire_numeric_authority(
                    reason="duplicated_writer_lock_failure_with_output"
                )
                raise LocalDeploymentPersistenceError(
                    "DuplicateHandle failure 同时返回 output；owner-crash-only"
                )
            slot.phase = "reusable_prepared"
            raise LocalDeploymentPersistenceError("DuplicateHandle 未返回 handle")
        if slot.value is None or slot.phase != "returned":
            self._retire_numeric_authority(
                reason="duplicated_writer_lock_success_without_output"
            )
            raise LocalDeploymentPersistenceError(
                "DuplicateHandle success 缺 output；owner-crash-only"
            )

    def _capture_expected_conflict(
        self,
        function: Callable[..., object],
        get_last_error: Callable[[], object],
        *arguments: object,
    ) -> int:
        """固定 conflict open；成功 handle 也先登记、关闭，再报告失败。"""

        self._assert_context()
        if not callable(function) or not callable(get_last_error):
            raise UnsafeLocalPath("writer conflict probe syscall seam 无效")
        slot = self._slot("unexpected_conflict_handle")
        if slot.phase != "reusable_prepared" or slot.value is not None:
            raise UnsafeLocalPath("writer conflict slot 不可重复取得")
        slot.phase = "syscall_in_progress"
        try:
            returned = function(*arguments)
            # state-owner assignment 必须先于 last-error 查询。
            acquired = self._commit_returned_value(
                slot, returned, failure_is_reusable=True
            )
            error = get_last_error()
        except BaseException as failure:
            if self._state != "owner_crash_only":
                self._retire_numeric_authority(
                    reason="writer_conflict_probe_outcome_unknown"
                )
            raise LocalDeploymentPersistenceError(
                "writer conflict probe outcome unknown；owner-crash-only"
            ) from failure
        if type(error) is not int or error < 0:
            self._retire_numeric_authority(
                reason="writer_conflict_probe_error_type_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "writer conflict probe last-error 无效；owner-crash-only"
            )
        if acquired:
            try:
                self._release_reusable_handle("unexpected_conflict_handle")
            except BaseException as close_error:
                raise LocalDeploymentPersistenceError(
                    "unexpected writer handle close 不可闭合"
                ) from close_error
            raise LocalDeploymentPersistenceError(
                "writer conflict probe 意外打开成功"
            )
        if error != 32:
            raise LocalDeploymentPersistenceError(
                "writer conflict probe 不是 ERROR_SHARING_VIOLATION"
            )
        return error

    def _borrow_handle(self, label: str) -> int:
        self._assert_context()
        slot = self._slot(label)
        if slot.phase != "returned" or type(slot.value) is not int:
            raise UnsafeLocalPath("writer lease slot 尚无 live handle")
        return slot.value

    def _release_reusable_handle(self, label: str) -> None:
        self._assert_context()
        slot = self._slot(label)
        if slot.phase != "returned" or type(slot.value) is not int:
            raise UnsafeLocalPath("writer lease reusable slot 尚无 live handle")
        try:
            CrashReleasedFileLock._windows_duplicate_close_source_call(slot.value)
        except BaseException as error:
            self._retire_numeric_authority(
                reason=f"{label}_close_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "writer lease handle close outcome unknown；owner-crash-only"
            ) from error
        slot.value = None
        slot.phase = "reusable_prepared"

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath(
                "Windows writer lease tracking close authority 不匹配"
            )
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "Windows writer lease handle 只允许 owner 进程退出回收"
            )
        self._state = "closing"
        close_error: BaseException | None = None
        for slot in reversed(self._slots):
            if slot.value is None:
                continue
            invalid = self._pointer_invalid()
            if (
                type(slot.value) is not int
                or slot.value < 1
                or slot.value >= invalid
            ):
                self._retire_numeric_authority(
                    reason=f"{slot.label}_workspace_close_numeric_authority_invalid"
                )
                close_error = LocalDeploymentPersistenceError(
                    "writer lease workspace close 缺 exact numeric authority"
                )
                break
            try:
                CrashReleasedFileLock._windows_duplicate_close_source_call(
                    slot.value
                )
            except BaseException as error:
                self._retire_numeric_authority(
                    reason=f"{slot.label}_workspace_close_outcome_unknown"
                )
                close_error = error
                break
            slot.value = None
            slot.phase = "reusable_prepared"
        if (
            close_error is not None
            or self._state == "owner_crash_only"
            or any(slot.value is not None for slot in self._slots)
        ):
            raise LocalDeploymentPersistenceError(
                "Windows writer lease tracking resource 关闭失败"
            ) from close_error
        self._state = "closed"
        self._workspace._release_windows_writer_lease_handle_tracking(self)

    @property
    def scope(self) -> str:
        self._assert_context()
        if self._tracking_kind == "transient":
            return _WINDOWS_WRITER_LEASE_HANDLE_TRACKING_SCOPE
        if self._tracking_kind == "steady":
            return _WINDOWS_STEADY_WRITER_LEASE_HANDLE_TRACKING_SCOPE
        raise DeploymentLockBusy("writer lease tracking kind 漂移")

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_windows_writer_lease_handle_tracking_public(self)

    def __enter__(self) -> "_WindowsWriterLeaseHandleTrackingCore":
        self._assert_context()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedWindowsWriterLeaseHandleTracking(
    _WindowsWriterLeaseHandleTrackingCore
):
    """Transient attempt 专属 writer lease handle owner。"""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("transient writer lease tracking 不允许派生")


class LockedWindowsSteadyWriterLeaseHandleTracking(
    _WindowsWriterLeaseHandleTrackingCore
):
    """Steady boot 专属 writer lease handle owner。"""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady writer lease tracking 不允许派生")


class LockedMutableCanarySqliteSet:
    """由 CREATE_NEW creator open instance 持续守护的 canary SQLite main。

    该能力只管理 attempt-local mutable main 的 open-instance identity 和关闭
    生命周期。它允许 SQLite 合法改变 size/mtime/bytes，但任何 main
    delete/rename/replacement、controller checkpoint 时的 sidecar 或未知成员都会
    fail closed。产品 Windows 路径从首次 ``CreateFileW`` 前已进入 workspace
    tracking；creator handle 本身一直保留到资源关闭，不存在 close/reopen 接管窗。
    """

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_acquisition_epoch",
        "_database",
        "_relative_parts",
        "_state",
        "_windows_handle",
        "_windows_identity",
        "_posix_descriptor",
        "_posix_identity",
        "_initial_main_sha256",
        "_retirement_sha256",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("mutable canary SQLite set 不允许派生")

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: "LockedAttemptWorkspace",
        database: str,
        relative_parts: tuple[str, ...],
        initial_main_sha256: str,
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_MUTABLE_CANARY_SQLITE_SET_TOKEN:
            raise UnsafeLocalPath(
                "mutable canary SQLite set 必须由 B2 façade 构造"
            )
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._acquisition_epoch = workspace._acquisition_epoch
        self._database = database
        self._relative_parts = relative_parts
        self._state = "acquiring"
        self._windows_handle: int | None = None
        self._windows_identity: tuple[int, int, int] | None = None
        self._posix_descriptor: int | None = None
        self._posix_identity: os.stat_result | None = None
        self._initial_main_sha256 = initial_main_sha256
        self._retirement_sha256: str | None = None

    def __reduce__(self) -> object:
        raise TypeError(
            "mutable canary SQLite set is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_context(self, *, states: set[str]) -> None:
        if self._state not in states:
            raise UnsafeLocalPath("mutable canary SQLite set 状态不允许该操作")
        self._workspace._assert_live()
        if (
            self._workspace._lock is not self._lock
            or self._workspace._safe_root is not self._persistence._safe_root
            or self._workspace._authority_token
            is not self._persistence._authority_token
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "mutable canary SQLite set authority/epoch 漂移"
            )

    @staticmethod
    def _pointer_invalid() -> int:
        import ctypes

        invalid = ctypes.c_void_p(-1).value
        if type(invalid) is not int:
            raise UnsafeLocalPath("无法计算 Windows INVALID_HANDLE_VALUE")
        return invalid

    def _retire_numeric_authority(self, *, reason: str) -> None:
        self._retirement_sha256 = _identity.identity_sha256(
            {
                "scope": "mutable_canary_sqlite_numeric_authority_retired",
                "attempt_id": self._workspace.attempt_id,
                "nonce": self._workspace.nonce,
                "database": self._database,
                "reason": reason,
                "windows_handle_present": self._windows_handle is not None,
                "posix_descriptor_present": self._posix_descriptor is not None,
            }
        )
        self._windows_handle = None
        self._posix_descriptor = None
        self._state = "owner_crash_only"
        self._lock._enter_owner_crash_only(reason=reason)

    @staticmethod
    def _windows_create_new_call(path: Path) -> int:
        if os.name != "nt":
            raise OSError("CreateFileW mutable canary seam 只允许 Windows")
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        return kernel32.CreateFileW(
            str(path),
            0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            0x00000001 | 0x00000002,  # SHARE_READ | SHARE_WRITE；明确不共享 delete
            None,
            1,  # CREATE_NEW
            0x00000080 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
            None,
        )

    @staticmethod
    def _windows_write_all_call(handle: int, raw: bytes) -> None:
        if os.name != "nt":
            raise OSError("WriteFile mutable canary seam 只允许 Windows")
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.WriteFile.argtypes = (
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        kernel32.WriteFile.restype = wintypes.BOOL
        offset = 0
        while offset < len(raw):
            block = raw[offset : offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(block)
            written = wintypes.DWORD()
            if not kernel32.WriteFile(
                wintypes.HANDLE(handle),
                buffer,
                len(block),
                ctypes.byref(written),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if int(written.value) != len(block):
                raise OSError("mutable canary WriteFile short write")
            offset += int(written.value)

    @staticmethod
    def _windows_flush_call(handle: int) -> None:
        if os.name != "nt":
            raise OSError("FlushFileBuffers mutable canary seam 只允许 Windows")
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
        kernel32.FlushFileBuffers.restype = wintypes.BOOL
        if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def _windows_identity_for_handle(handle: int) -> tuple[int, int, int]:
        details = LockedStateSqliteSource._windows_handle_details(handle)
        attributes, links, _size, _mtime, volume, high, low = details
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT or links != 1:
            raise UnsafeLocalPath(
                "mutable canary SQLite creator handle 不是普通 single-link main"
            )
        return volume, high, low

    def _capture_windows_creator(self) -> None:
        self._assert_context(states={"acquiring"})
        target = self._workspace._target(self._relative_parts)
        try:
            # CreateFileW 返回后的第一项 state-owner 动作是提交 handle。
            self._windows_handle = self._windows_create_new_call(target)
        except BaseException as error:
            self._retire_numeric_authority(
                reason=f"mutable_{self._database}_create_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "mutable canary CREATE_NEW outcome unknown；owner-crash-only"
            ) from error
        invalid = self._pointer_invalid()
        if self._windows_handle in {None, 0, -1, invalid}:
            self._windows_handle = None
            raise UnsafeLocalPath("mutable canary SQLite main 已存在或无法创建")
        if (
            type(self._windows_handle) is not int
            or self._windows_handle < 1
            or self._windows_handle >= invalid
        ):
            self._retire_numeric_authority(
                reason=f"mutable_{self._database}_create_handle_invalid"
            )
            raise LocalDeploymentPersistenceError(
                "mutable canary CREATE_NEW handle 无法安全管理"
            )

    def _capture_posix_creator(self) -> None:
        self._assert_context(states={"acquiring"})
        if not self._persistence._allow_posix_test_only:
            raise UnsafeLocalPath("POSIX mutable canary 只允许显式 test-only")
        parent = self._workspace._parent_guard(self._relative_parts)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = parent.open_file(self._relative_parts[-1], flags, 0o600)
            # open 返回后的第一项 state-owner 动作是提交 descriptor。
            self._posix_descriptor = descriptor
        except FileExistsError as error:
            raise UnsafeLocalPath("mutable canary SQLite main 已存在") from error
        except BaseException as error:
            self._retire_numeric_authority(
                reason=f"mutable_{self._database}_posix_create_outcome_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "test-only mutable canary create outcome unknown"
            ) from error
        try:
            self._posix_identity = os.fstat(descriptor)
        except BaseException as error:
            self._retire_numeric_authority(
                reason=f"mutable_{self._database}_posix_identity_unknown"
            )
            raise LocalDeploymentPersistenceError(
                "test-only mutable canary identity outcome unknown"
            ) from error

    def _write_and_flush(self, raw: bytes) -> None:
        if os.name == "nt":
            handle = self._windows_handle
            if type(handle) is not int:
                raise UnsafeLocalPath("mutable canary creator handle 缺失")
            try:
                self._windows_write_all_call(handle, raw)
                self._windows_flush_call(handle)
            except BaseException as error:
                self._retire_numeric_authority(
                    reason=f"mutable_{self._database}_write_flush_outcome_unknown"
                )
                raise LocalDeploymentPersistenceError(
                    "mutable canary write/flush outcome unknown；owner-crash-only"
                ) from error
            return
        descriptor = self._posix_descriptor
        if type(descriptor) is not int:
            raise UnsafeLocalPath("test-only mutable canary descriptor 缺失")
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short mutable canary write")
                view = view[written:]
            os.fsync(descriptor)
        except BaseException as error:
            raise UnsafeLocalPath("test-only mutable canary write/flush 失败") from error

    def _member_names(self) -> set[str]:
        parent = self._workspace._target(self._relative_parts[:-1])
        return {entry.name for entry in os.scandir(parent)}

    def _checkpoint_identity(self, *, require_initial_hash: bool) -> bytes:
        self._assert_context(states={"acquiring", "live"})
        expected_name = self._relative_parts[-1]
        observed_names = self._member_names()
        expected_names = self._workspace._expected_mutable_canary_member_names(
            self._relative_parts[:-1]
        )
        if expected_name not in expected_names or observed_names != expected_names:
            raise UnsafeLocalPath(
                "mutable canary controller checkpoint 成员集合漂移"
            )
        observed = self._workspace._preflight_parts(
            self._relative_parts,
            expected_kind="file",
            allow_absent=False,
        )
        if observed is None or getattr(observed, "st_nlink", 1) != 1:
            raise UnsafeLocalPath("mutable canary SQLite main 身份缺失")
        target = self._workspace._target(self._relative_parts)
        if os.name == "nt":
            handle = self._windows_handle
            if type(handle) is not int:
                raise UnsafeLocalPath("mutable canary creator handle 已失效")
            identity = self._windows_identity_for_handle(handle)
            if self._windows_identity is None:
                self._windows_identity = identity
            elif identity != self._windows_identity:
                raise UnsafeLocalPath("mutable canary creator open instance 漂移")
            final_path = _BoundDirectory._windows_final_path(handle)
            if PureWindowsPath(final_path).as_posix().casefold() != PureWindowsPath(
                str(target.resolve(strict=True))
            ).as_posix().casefold():
                raise UnsafeLocalPath("mutable canary main directory entry 已替换")
            raw = target.read_bytes()
            if self._windows_identity_for_handle(handle) != identity:
                raise UnsafeLocalPath("mutable canary main 在读取期间漂移")
        else:
            descriptor = self._posix_descriptor
            if type(descriptor) is not int:
                raise UnsafeLocalPath("test-only mutable canary descriptor 已失效")
            opened = os.fstat(descriptor)
            if self._posix_identity is None:
                self._posix_identity = opened
            elif not _same_file_identity(self._posix_identity, opened):
                raise UnsafeLocalPath("test-only mutable canary open instance 漂移")
            if not _same_file_identity(opened, observed):
                raise UnsafeLocalPath("test-only mutable canary main 已替换")
            if hasattr(os, "pread"):
                raw = os.pread(descriptor, opened.st_size, 0)
            else:  # pragma: no cover - Windows 产品路径不走 POSIX descriptor。
                position = os.lseek(descriptor, 0, os.SEEK_CUR)
                os.lseek(descriptor, 0, os.SEEK_SET)
                raw = os.read(descriptor, opened.st_size)
                os.lseek(descriptor, position, os.SEEK_SET)
            if not _same_file_identity(opened, os.fstat(descriptor)):
                raise UnsafeLocalPath("test-only mutable canary main 读取时漂移")
        if require_initial_hash and hashlib.sha256(raw).hexdigest() != self._initial_main_sha256:
            raise UnsafeLocalPath("mutable canary initial main bytes/hash 漂移")
        return raw

    def _acquire(self, raw: bytes) -> None:
        self._assert_context(states={"acquiring"})
        if self._workspace._preflight_parts(
            self._relative_parts, expected_kind="file", allow_absent=True
        ) is not None:
            raise UnsafeLocalPath("mutable canary SQLite main 必须 CREATE_NEW")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = (*self._relative_parts[:-1], self._relative_parts[-1] + suffix)
            if self._workspace._preflight_parts(
                sidecar, expected_kind="file", allow_absent=True
            ) is not None:
                raise UnsafeLocalPath("mutable canary SQLite sidecar 必须初始 absent")
        if os.name == "nt":
            self._capture_windows_creator()
        else:
            self._capture_posix_creator()
        self._write_and_flush(raw)
        self._checkpoint_identity(require_initial_hash=True)
        self._state = "live"

    @property
    def scope(self) -> str:
        self._assert_context(states={"live"})
        return _MUTABLE_CANARY_SQLITE_SET_SCOPE

    @property
    def database(self) -> str:
        self._assert_context(states={"live"})
        return self._database

    @property
    def members(self) -> tuple[str, ...]:
        self._assert_context(states={"live"})
        self._checkpoint_identity(require_initial_hash=False)
        return ("main",)

    @property
    def initial_main_sha256(self) -> str:
        self._assert_context(states={"live"})
        return self._initial_main_sha256

    def read_main_bytes(self) -> bytes:
        return self._checkpoint_identity(require_initial_hash=False)

    def checkpoint_closed(self) -> None:
        self._checkpoint_identity(require_initial_hash=False)

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("mutable canary SQLite close authority 不匹配")
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise LocalDeploymentPersistenceError(
                "mutable canary SQLite 只允许 owner 进程退出回收"
            )
        self._state = "closing"
        if self._windows_handle is not None:
            handle = self._windows_handle
            try:
                CrashReleasedFileLock._windows_duplicate_close_source_call(handle)
            except BaseException as error:
                self._retire_numeric_authority(
                    reason=f"mutable_{self._database}_close_outcome_unknown"
                )
                raise LocalDeploymentPersistenceError(
                    "mutable canary SQLite close outcome unknown；owner-crash-only"
                ) from error
            self._windows_handle = None
        if self._posix_descriptor is not None:
            descriptor = self._posix_descriptor
            initial = self._posix_identity
            if initial is None:
                raise UnsafeLocalPath("mutable canary descriptor 缺初始身份")
            try:
                os.close(descriptor)
            except OSError as error:
                try:
                    no_longer_exact = _descriptor_no_longer_exact(
                        descriptor, initial
                    )
                except BaseException as proof_error:
                    raise UnsafeLocalPath(
                        "mutable canary descriptor close 后身份不明"
                    ) from proof_error
                if not no_longer_exact:
                    raise UnsafeLocalPath(
                        "mutable canary descriptor close 失败"
                    ) from error
            self._posix_descriptor = None
        if self._windows_handle is not None or self._posix_descriptor is not None:
            raise LocalDeploymentPersistenceError(
                "mutable canary SQLite resource 未机械闭合"
            )
        self._state = "closed"
        self._workspace._release_mutable_canary_sqlite_set(self)

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_mutable_canary_sqlite_set_public(self)

    def __enter__(self) -> "LockedMutableCanarySqliteSet":
        self._assert_context(states={"live"})
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


@dataclass(slots=True)
class _PinnedSqliteMember:
    label: str
    relative_parts: tuple[str, ...]
    descriptor: int | None
    initial: os.stat_result | None


class PinnedSqliteSet:
    """不暴露绝对路径的 main/WAL/SHM open-handle 集合。"""

    def __init__(
        self,
        *,
        workspace: "LockedAttemptWorkspace",
        members: tuple[_PinnedSqliteMember, ...],
        _construction_token: object,
    ):
        if _construction_token is not _PINNED_SQLITE_TOKEN:
            raise UnsafeLocalPath("SQLite pin 必须由 attempt workspace 构造")
        self._workspace = workspace
        self._members = members
        self._closed = False

    @property
    def members(self) -> tuple[str, ...]:
        if self._closed:
            return ()
        return tuple(
            member.label for member in self._members if member.descriptor is not None
        )

    def _member(self, label: str) -> _PinnedSqliteMember:
        if label not in {"main", "wal", "shm"}:
            raise UnsafeLocalPath("SQLite member 只允许 main/wal/shm")
        for member in self._members:
            if member.label == label:
                if member.descriptor is None:
                    raise UnsafeLocalPath(f"SQLite {label} 在 pin 时不存在")
                return member
        raise UnsafeLocalPath("SQLite member 未绑定")

    def read_bytes(self, label: str) -> bytes:
        self._workspace._assert_live()
        if self._closed:
            raise UnsafeLocalPath("SQLite pin 已关闭")
        member = self._member(label)
        assert member.descriptor is not None and member.initial is not None
        before = os.fstat(member.descriptor)
        if (
            not _same_file_identity(before, member.initial)
            or not stat.S_ISREG(before.st_mode)
            or _is_reparse(before)
            or getattr(before, "st_nlink", 1) != 1
        ):
            raise UnsafeLocalPath("SQLite pinned member 身份漂移")
        os.lseek(member.descriptor, 0, os.SEEK_SET)
        blocks: list[bytes] = []
        while True:
            block = os.read(member.descriptor, 1024 * 1024)
            if not block:
                break
            blocks.append(block)
        after = os.fstat(member.descriptor)
        if (
            not _same_file_identity(before, after)
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise UnsafeLocalPath("SQLite pinned member 在读取期间漂移")
        return b"".join(blocks)

    def assert_unchanged(self) -> None:
        self._workspace._assert_live()
        if self._closed:
            raise UnsafeLocalPath("SQLite pin 已关闭")
        for member in self._members:
            observed = self._workspace._preflight_parts(
                member.relative_parts,
                expected_kind="file",
                allow_absent=True,
            )
            if member.initial is None:
                if observed is not None:
                    raise UnsafeLocalPath("SQLite absent sidecar 在 pin 后出现")
                continue
            if member.descriptor is None or observed is None:
                raise UnsafeLocalPath("SQLite pinned member 在 pin 后消失")
            opened = os.fstat(member.descriptor)
            if (
                not _same_file_identity(member.initial, opened)
                or not _same_file_identity(opened, observed)
                or member.initial.st_size != opened.st_size
                or member.initial.st_mtime_ns != opened.st_mtime_ns
                or getattr(opened, "st_nlink", 1) != 1
            ):
                raise UnsafeLocalPath("SQLite pinned member 在 pin 后漂移")

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("SQLite pin 只能由所属 workspace 关闭")
        if self._closed:
            return
        close_error: BaseException | None = None
        for member in self._members:
            descriptor = member.descriptor
            initial = member.initial
            if descriptor is None:
                continue
            if initial is None:
                raise UnsafeLocalPath("SQLite pin descriptor 缺初始身份")
            try:
                os.close(descriptor)
            except OSError as error:
                try:
                    no_longer_exact = _descriptor_no_longer_exact(
                        descriptor, initial
                    )
                except BaseException as proof_error:
                    no_longer_exact = False
                    if close_error is None:
                        close_error = proof_error
                if not no_longer_exact:
                    if close_error is None:
                        close_error = error
                    continue
            member.descriptor = None
        if any(member.descriptor is not None for member in self._members):
            if close_error is None:
                close_error = UnsafeLocalPath(
                    "SQLite pin 仍有未机械闭合的 descriptor"
                )
            raise UnsafeLocalPath("SQLite pin 关闭失败") from close_error
        self._closed = True
        self._workspace._release_pin(self)

    def close(self) -> None:
        if self._closed:
            return
        self._workspace._close_pin_public(self)

    def __enter__(self) -> "PinnedSqliteSet":
        if self._closed:
            raise UnsafeLocalPath("SQLite pin 已关闭")
        self._workspace._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class LockedNewFile:
    """A write-only capability bound to one live workspace acquisition epoch."""

    __slots__ = ("_workspace", "_initial", "_closed")

    def __init__(
        self,
        *,
        workspace: "LockedAttemptWorkspace",
        initial: os.stat_result | None = None,
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_NEW_FILE_TOKEN:
            raise UnsafeLocalPath("LockedNewFile 必须由 attempt workspace 构造")
        if initial is None:
            raise UnsafeLocalPath("LockedNewFile 必须绑定初始 file identity")
        self._workspace = workspace
        self._initial = initial
        self._closed = False

    def _assert_writable(self) -> int:
        if self._closed:
            raise UnsafeLocalPath("LockedNewFile 已关闭")
        return self._workspace._open_file_descriptor(self)

    def write_all(self, raw: bytes) -> int:
        if not isinstance(raw, bytes):
            raise UnsafeLocalPath("LockedNewFile payload 必须是 bytes")
        self._assert_writable()
        view = memoryview(raw)
        total = 0
        try:
            while view:
                descriptor = self._assert_writable()
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short LockedNewFile write")
                total += written
                view = view[written:]
        except OSError as error:
            raise UnsafeLocalPath("LockedNewFile write_all 失败") from error
        return total

    def fsync(self) -> None:
        descriptor = self._assert_writable()
        try:
            os.fsync(descriptor)
        except OSError as error:
            raise UnsafeLocalPath("LockedNewFile fsync 失败") from error

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("LockedNewFile 只能由所属 workspace 关闭")
        if self._closed:
            return
        descriptor = self._workspace._open_file_descriptor_for_close(
            self,
            _close_token=_close_token,
        )
        try:
            os.close(descriptor)
        except OSError as error:
            try:
                no_longer_exact = _descriptor_no_longer_exact(
                    descriptor, self._initial
                )
            except BaseException as proof_error:
                raise UnsafeLocalPath(
                    "LockedNewFile close 后无法证明 descriptor 身份"
                ) from proof_error
            if not no_longer_exact:
                raise UnsafeLocalPath("LockedNewFile close 失败") from error
        self._workspace._release_open_file_after_proven_close(
            self,
            descriptor=descriptor,
            _close_token=_close_token,
        )
        self._closed = True

    def close(self) -> None:
        if self._closed:
            return
        self._workspace._close_file_public(self)

    def __enter__(self) -> "LockedNewFile":
        self._assert_writable()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class LockedSteadyBootWorkspace:
    """无 persistent attempt 身份的同 epoch steady boot resource owner。

    本对象只绑定 process-local B2 lock acquisition 与 fresh boot nonce。它没有
    attempt/journal/evidence/file/cleanup API，因而不能冒充 transient workspace。
    后续 steady SCM、endpoint、writer 与 service lifecycle 只能登记到本 owner。
    """

    __slots__ = (
        "_persistence",
        "_safe_root",
        "_lock",
        "_authority_token",
        "_acquisition_epoch",
        "_boot_nonce",
        "_failure_recovery_raw",
        "_steady_release_closures",
        "_steady_tooling_observations",
        "_steady_receipt_lineages",
        "_steady_legacy_c_fences",
        "_steady_start_authorizations",
        "_steady_service_child_lifecycles",
        "_steady_admission_authorizations",
        "_steady_windows_scm_process_handle_tracking",
        "_steady_windows_endpoint_observations",
        "_steady_windows_writer_lease_handle_tracking",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady boot workspace 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady boot workspace 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        safe_root: _SafeRoot,
        lock: CrashReleasedFileLock,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
        boot_nonce: str,
        failure_recovery_authorization: Mapping[str, object] | None,
        _construction_token: object,
    ):
        if _construction_token is not _STEADY_BOOT_WORKSPACE_TOKEN:
            raise DeploymentLockBusy(
                "steady boot workspace 必须由 persistence façade 构造"
            )
        if re.fullmatch(r"[0-9a-f]{48}", boot_nonce) is None:
            raise DeploymentLockBusy("steady boot nonce 必须是 fresh 192-bit hex")
        object.__setattr__(self, "_sealed", False)
        self._persistence = persistence
        self._safe_root = safe_root
        self._lock = lock
        self._authority_token = authority_token
        self._acquisition_epoch = acquisition_epoch
        self._boot_nonce = boot_nonce
        self._failure_recovery_raw = (
            None
            if failure_recovery_authorization is None
            else _identity.canonical_bytes(
                _validate_failure_steady_recovery_authorization(
                    failure_recovery_authorization
                )
            )
        )
        self._steady_release_closures: set[LockedSteadyReleaseClosures] = set()
        self._steady_tooling_observations: set[object] = set()
        self._steady_receipt_lineages: set[object] = set()
        self._steady_legacy_c_fences: set[object] = set()
        self._steady_start_authorizations: set[object] = set()
        self._steady_service_child_lifecycles: set[object] = set()
        self._steady_admission_authorizations: set[object] = set()
        self._steady_windows_scm_process_handle_tracking: set[
            LockedWindowsSteadyScmProcessHandleTracking
        ] = set()
        self._steady_windows_endpoint_observations: set[object] = set()
        self._steady_windows_writer_lease_handle_tracking: set[
            LockedWindowsSteadyWriterLeaseHandleTracking
        ] = set()
        self._state = "live"
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady boot workspace is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> None:
        if self._state != "live":
            raise DeploymentLockBusy("steady boot workspace 不再 live")
        self._lock._assert_epoch_held(
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )

    @property
    def scope(self) -> str:
        self._assert_live()
        return _STEADY_BOOT_WORKSPACE_SCOPE

    @property
    def boot_nonce(self) -> str:
        self._assert_live()
        return self._boot_nonce

    @property
    def failure_recovery_authorization(self) -> Mapping[str, object] | None:
        self._assert_live()
        if self._failure_recovery_raw is None:
            return None
        value = json.loads(self._failure_recovery_raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise DeploymentJournalError(
                "failure recovery workspace authorization 类型漂移"
            )
        return _validate_failure_steady_recovery_authorization(value)

    def _assert_resource_owner(self) -> None:
        if self._state not in {"live", "closing"}:
            raise DeploymentLockBusy("steady boot workspace 不再持有资源")
        self._lock._assert_epoch_owner(
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )

    def _register_steady_release_closures(
        self, resource: "LockedSteadyReleaseClosures"
    ) -> None:
        self._assert_live()
        if self._steady_release_closures:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一组 active/prior release closures"
            )
        self._steady_release_closures.add(resource)

    def _release_steady_release_closures(
        self, resource: "LockedSteadyReleaseClosures"
    ) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_release_closures:
            raise DeploymentLockBusy(
                "steady release closures 未登记到当前 workspace"
            )
        self._steady_release_closures.remove(resource)

    def _close_steady_release_closures_public(
        self, resource: "LockedSteadyReleaseClosures"
    ) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_release_closures:
            raise DeploymentLockBusy(
                "steady release closures 不属于当前 workspace"
            )
        resource._close_from_workspace(
            _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN
        )

    def _register_steady_tooling_observation(self, resource: object) -> None:
        self._assert_live()
        if self._steady_tooling_observations:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 tooling live observation"
            )
        self._steady_tooling_observations.add(resource)

    def _release_steady_tooling_observation(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_tooling_observations:
            raise DeploymentLockBusy(
                "steady tooling observation 未登记到当前 workspace"
            )
        self._steady_tooling_observations.remove(resource)

    def _close_steady_tooling_observation_public(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_tooling_observations:
            raise DeploymentLockBusy(
                "steady tooling observation 不属于当前 workspace"
            )
        resource._close_from_workspace(self)  # type: ignore[attr-defined]

    def _register_steady_receipt_lineage(self, resource: object) -> None:
        self._assert_live()
        if self._steady_receipt_lineages:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 receipt lineage"
            )
        self._steady_receipt_lineages.add(resource)

    def _release_steady_receipt_lineage(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_receipt_lineages:
            raise DeploymentLockBusy("steady receipt lineage 未登记到当前 workspace")
        self._steady_receipt_lineages.remove(resource)

    def _close_steady_receipt_lineage_public(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_receipt_lineages:
            raise DeploymentLockBusy("steady receipt lineage 不属于当前 workspace")
        resource._close_from_workspace(self)  # type: ignore[attr-defined]

    def _register_steady_legacy_c_fence(self, resource: object) -> None:
        self._assert_live()
        if self._steady_legacy_c_fences:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个旧 C live fence"
            )
        self._steady_legacy_c_fences.add(resource)

    def _release_steady_legacy_c_fence(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_legacy_c_fences:
            raise DeploymentLockBusy("旧 C live fence 未登记到当前 workspace")
        self._steady_legacy_c_fences.remove(resource)

    def _close_steady_legacy_c_fence_public(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_legacy_c_fences:
            raise DeploymentLockBusy("旧 C live fence 不属于当前 workspace")
        resource._close_from_workspace(self)  # type: ignore[attr-defined]

    def _register_steady_start_authorization(self, resource: object) -> None:
        self._assert_live()
        if self._steady_start_authorizations:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 exact start authorization"
            )
        self._steady_start_authorizations.add(resource)

    def _release_steady_start_authorization(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_start_authorizations:
            raise DeploymentLockBusy("steady start authorization 未登记")
        self._steady_start_authorizations.remove(resource)

    def _close_steady_start_authorization_public(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_start_authorizations:
            raise DeploymentLockBusy("steady start authorization 不属于当前 workspace")
        resource._close_from_workspace(self)  # type: ignore[attr-defined]

    def _register_windows_scm_process_handle_tracking(
        self, tracking: LockedWindowsSteadyScmProcessHandleTracking
    ) -> None:
        self._assert_live()
        if (
            type(tracking) is not LockedWindowsSteadyScmProcessHandleTracking
            or tracking._tracking_kind != "steady"
            or tracking._workspace is not self
            or tracking._lock is not self._lock
            or tracking._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "steady Windows SCM/process tracking 不属于当前 workspace/epoch"
            )
        if self._steady_windows_scm_process_handle_tracking:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 live Windows SCM observation tracking"
            )
        self._steady_windows_scm_process_handle_tracking.add(tracking)

    def _release_windows_scm_process_handle_tracking(
        self, tracking: LockedWindowsSteadyScmProcessHandleTracking
    ) -> None:
        self._assert_resource_owner()
        if tracking._state != "closed":
            raise UnsafeLocalPath("steady Windows SCM/process tracking 未机械闭合")
        if tracking not in self._steady_windows_scm_process_handle_tracking:
            raise UnsafeLocalPath("steady Windows SCM/process tracking 未登记")
        self._steady_windows_scm_process_handle_tracking.remove(tracking)

    def _close_windows_scm_process_handle_tracking_public(
        self, tracking: LockedWindowsSteadyScmProcessHandleTracking
    ) -> None:
        self._assert_resource_owner()
        if tracking not in self._steady_windows_scm_process_handle_tracking:
            raise DeploymentLockBusy(
                "steady Windows SCM/process tracking 不属于当前 workspace"
            )
        if (
            self._steady_windows_endpoint_observations
            or self._steady_windows_writer_lease_handle_tracking
        ):
            raise DeploymentLockBusy(
                "steady endpoint/writer live 时不得先关闭 SCM tracking"
            )
        try:
            tracking._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            if tracking._state != "owner_crash_only":
                object.__setattr__(self, "_state", "closing")
            raise

    def _register_steady_windows_endpoint_observation(
        self, resource: object
    ) -> None:
        from .local_windows_endpoint_observer import (
            LockedSteadyWindowsEndpointObservation,
        )

        self._assert_live()
        if self._steady_windows_endpoint_observations:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 live endpoint observation"
            )
        tracking = getattr(resource, "_scm_observation", None)
        tracking = getattr(tracking, "_tracking", None)
        if (
            type(resource) is not LockedSteadyWindowsEndpointObservation
            or type(tracking)
            is not LockedWindowsSteadyScmProcessHandleTracking
            or tracking
            not in self._steady_windows_scm_process_handle_tracking
        ):
            raise DeploymentLockBusy(
                "steady endpoint observation 未绑定当前 SCM tracking"
            )
        self._steady_windows_endpoint_observations.add(resource)

    def _release_steady_windows_endpoint_observation(
        self, resource: object
    ) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_windows_endpoint_observations:
            raise DeploymentLockBusy("steady endpoint observation 未登记")
        self._steady_windows_endpoint_observations.remove(resource)

    def _close_steady_windows_endpoint_observation_public(
        self, resource: object
    ) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_windows_endpoint_observations:
            raise DeploymentLockBusy(
                "steady endpoint observation 不属于当前 workspace"
            )
        if self._steady_windows_writer_lease_handle_tracking:
            raise DeploymentLockBusy(
                "steady writer tracking live 时不得先关闭 endpoint"
            )
        resource._close_from_workspace(self)  # type: ignore[attr-defined]

    def _register_windows_writer_lease_handle_tracking(
        self, tracking: LockedWindowsSteadyWriterLeaseHandleTracking
    ) -> None:
        self._assert_live()
        if (
            type(tracking)
            is not LockedWindowsSteadyWriterLeaseHandleTracking
            or tracking._tracking_kind != "steady"
            or tracking._workspace is not self
            or tracking._lock is not self._lock
            or tracking._acquisition_epoch is not self._acquisition_epoch
            or tracking._scm_tracking
            not in self._steady_windows_scm_process_handle_tracking
        ):
            raise DeploymentLockBusy(
                "steady writer lease tracking 不属于当前 workspace/SCM epoch"
            )
        if self._steady_windows_writer_lease_handle_tracking:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 live writer lease tracking"
            )
        self._steady_windows_writer_lease_handle_tracking.add(tracking)

    def _release_windows_writer_lease_handle_tracking(
        self, tracking: LockedWindowsSteadyWriterLeaseHandleTracking
    ) -> None:
        self._assert_resource_owner()
        if tracking._state != "closed":
            raise UnsafeLocalPath("steady writer lease tracking 未机械闭合")
        if tracking not in self._steady_windows_writer_lease_handle_tracking:
            raise UnsafeLocalPath("steady writer lease tracking 未登记")
        self._steady_windows_writer_lease_handle_tracking.remove(tracking)

    def _close_windows_writer_lease_handle_tracking_public(
        self, tracking: LockedWindowsSteadyWriterLeaseHandleTracking
    ) -> None:
        self._assert_resource_owner()
        if tracking not in self._steady_windows_writer_lease_handle_tracking:
            raise DeploymentLockBusy(
                "steady writer lease tracking 不属于当前 workspace"
            )
        try:
            tracking._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            if tracking._state != "owner_crash_only":
                object.__setattr__(self, "_state", "closing")
            raise

    def _register_steady_service_child_lifecycle(self, lifecycle: object) -> None:
        from .local_windows_job_child_launcher import (
            LockedServiceChildLaunchLifecycle,
        )

        self._assert_live()
        if (
            type(lifecycle) is not LockedServiceChildLaunchLifecycle
            or lifecycle._workspace is not self  # noqa: SLF001
            or lifecycle._authorization
            not in self._steady_start_authorizations  # noqa: SLF001
            or lifecycle._state != "launching"  # noqa: SLF001
        ):
            raise DeploymentLockBusy(
                "steady service child lifecycle 不属于当前 workspace/authorization"
            )
        if self._steady_service_child_lifecycles:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 service child lifecycle"
            )
        self._steady_service_child_lifecycles.add(lifecycle)

    def _release_steady_service_child_lifecycle(self, lifecycle: object) -> None:
        self._assert_resource_owner()
        if lifecycle not in self._steady_service_child_lifecycles:
            raise DeploymentLockBusy("steady service child lifecycle 未登记")
        if lifecycle._state not in {"closed", "promoted"}:  # noqa: SLF001
            raise DeploymentLockBusy(
                "steady service child lifecycle 尚未机械关闭或 promotion"
            )
        self._steady_service_child_lifecycles.remove(lifecycle)

    def _register_steady_admission_authorization(self, resource: object) -> None:
        from .local_steady_admission_authorization import (
            LockedSteadyAdmissionPrepareAuthorization,
        )

        self._assert_live()
        if (
            type(resource) is not LockedSteadyAdmissionPrepareAuthorization
            or resource._workspace is not self  # noqa: SLF001
            or resource._state != "live"  # noqa: SLF001
        ):
            raise DeploymentLockBusy(
                "steady admission prepare authorization 不属于当前 workspace"
            )
        if self._steady_admission_authorizations:
            raise DeploymentLockBusy(
                "同一 steady workspace 只允许一个 admission authorization"
            )
        self._steady_admission_authorizations.add(resource)

    def _replace_steady_admission_authorization(
        self, source: object, destination: object
    ) -> None:
        from .local_steady_admission_authorization import (
            LockedSteadyAdmissionCommitAuthorization,
            LockedSteadyAdmissionPrepareAuthorization,
        )

        self._assert_resource_owner()
        if (
            type(source) is not LockedSteadyAdmissionPrepareAuthorization
            or type(destination) is not LockedSteadyAdmissionCommitAuthorization
            or source not in self._steady_admission_authorizations
            or source._workspace is not self  # noqa: SLF001
            or destination._workspace is not self  # noqa: SLF001
            or source._lifetime is not destination._lifetime  # noqa: SLF001
            or source._state != "prepared"  # noqa: SLF001
            or destination._state != "live"  # noqa: SLF001
        ):
            raise DeploymentLockBusy(
                "steady admission prepare→commit replacement provenance 漂移"
            )
        # Destination first, source retirement second: no unowned Job/pipe cut.
        self._steady_admission_authorizations.add(destination)
        object.__setattr__(source, "_state", "consumed")
        self._steady_admission_authorizations.remove(source)

    def _release_steady_admission_authorization(self, resource: object) -> None:
        self._assert_resource_owner()
        if resource not in self._steady_admission_authorizations:
            raise DeploymentLockBusy("steady admission authorization 未登记")
        self._steady_admission_authorizations.remove(resource)

    def _close_and_unregister(self) -> None:
        if self._state == "closed":
            return
        if self._state not in {"live", "closing"}:
            raise DeploymentLockBusy("steady boot workspace close state 非法")
        self._lock._assert_epoch_owner(
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )
        object.__setattr__(self, "_state", "closing")
        for resource in tuple(self._steady_admission_authorizations):
            resource._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_admission_authorizations:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace admission authorization 未机械关闭"
            )
        for lifecycle in tuple(self._steady_service_child_lifecycles):
            lifecycle._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_service_child_lifecycles:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace service child lifecycle 未机械关闭"
            )
        for tracking in tuple(
            self._steady_windows_writer_lease_handle_tracking
        ):
            tracking._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        if self._steady_windows_writer_lease_handle_tracking:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace writer lease tracking 未机械关闭"
            )
        for resource in tuple(self._steady_windows_endpoint_observations):
            resource._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_windows_endpoint_observations:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace endpoint observation 未机械关闭"
            )
        for tracking in tuple(
            self._steady_windows_scm_process_handle_tracking
        ):
            tracking._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        if self._steady_windows_scm_process_handle_tracking:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace Windows SCM/process tracking 未机械关闭"
            )
        for resource in tuple(self._steady_start_authorizations):
            resource._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_start_authorizations:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace start authorization 未机械关闭"
            )
        for resource in tuple(self._steady_legacy_c_fences):
            resource._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_legacy_c_fences:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace 旧 C live fence 未机械关闭"
            )
        for resource in tuple(self._steady_receipt_lineages):
            resource._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_receipt_lineages:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace receipt lineage 未机械关闭"
            )
        for resource in tuple(self._steady_tooling_observations):
            resource._close_from_workspace(self)  # type: ignore[attr-defined]
        if self._steady_tooling_observations:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace tooling observation 未机械关闭"
            )
        for resource in tuple(self._steady_release_closures):
            resource._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN
            )
        if self._steady_release_closures:
            raise LocalDeploymentPersistenceError(
                "steady boot workspace release closure 未机械关闭"
            )
        self._lock._unregister_workspace(
            self,
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )
        object.__setattr__(self, "_state", "closed")

    def _close_for_lock_release(
        self,
        *,
        lock: CrashReleasedFileLock,
        acquisition_epoch: _LockAcquisitionEpoch,
        _close_token: object,
    ) -> None:
        if (
            _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN
            or lock is not self._lock
            or acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy("steady boot workspace release authority 不匹配")
        self._close_and_unregister()

    def close(self) -> None:
        if self._state == "closed":
            return
        self._close_and_unregister()

    def __enter__(self) -> "LockedSteadyBootWorkspace":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedSteadyPairStaticFacts:
    """同一 steady epoch 的 exact pair/state 静态事实；不是 start authority。"""

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_acquisition_epoch",
        "_material_raw",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady pair static facts 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady pair static facts 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        acquisition_epoch: _LockAcquisitionEpoch,
        material: Mapping[str, object],
        _construction_token: object,
    ):
        if _construction_token is not _LOCKED_STEADY_PAIR_STATIC_FACTS_TOKEN:
            raise DeploymentLockBusy(
                "steady pair static facts 必须由 persistence façade 构造"
            )
        object.__setattr__(self, "_sealed", False)
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._acquisition_epoch = acquisition_epoch
        self._material_raw = _identity.canonical_bytes(material)
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady pair static facts are process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> Mapping[str, object]:
        if (
            type(self._workspace) is not LockedSteadyBootWorkspace
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy("steady pair facts workspace/epoch 漂移")
        material = self._persistence._derive_steady_pair_static_material(
            self._lock,
            self._workspace,
        )
        if _identity.canonical_bytes(material) != self._material_raw:
            raise RetentionPlanningError("steady pair static facts 已漂移")
        return material

    @property
    def scope(self) -> str:
        self._assert_live()
        return _STEADY_PAIR_STATIC_FACTS_SCOPE

    @property
    def authority_kind(self) -> str:
        return str(self._assert_live()["authority_kind"])

    @property
    def runtime_state_kind(self) -> str:
        return str(self._assert_live()["runtime_state_kind"])

    @property
    def boot_nonce(self) -> str:
        return str(self._assert_live()["boot_nonce"])

    @property
    def active_release_sha256(self) -> str:
        return str(self._assert_live()["active_release_sha256"])

    @property
    def binding_sha256(self) -> str:
        return str(self._assert_live()["binding_sha256"])

    @property
    def retention_aggregate_sha256(self) -> str:
        return str(self._assert_live()["retention_aggregate_sha256"])

    @property
    def state_identity_sha256(self) -> str:
        return str(self._assert_live()["state_identity_sha256"])

    @property
    def release_ref(self) -> Mapping[str, object]:
        release = self._assert_live()["release"]
        cloned = json.loads(_identity.canonical_bytes(release).decode("utf-8"))
        if type(cloned) is not dict:
            raise RetentionPlanningError("steady active release ref clone 类型漂移")
        return cloned

    @property
    def prior_release_ref(self) -> Mapping[str, object] | None:
        release = self._assert_live()["prior_release"]
        if release is None:
            return None
        cloned = json.loads(_identity.canonical_bytes(release).decode("utf-8"))
        if type(cloned) is not dict:
            raise RetentionPlanningError("steady prior release ref clone 类型漂移")
        return cloned


class _SteadyReleaseClosureWorkspaceAdapter:
    """仅供既有 no-share/namespace 引擎使用的非导出适配器。"""

    __slots__ = ("_owner", "_lock", "_acquisition_epoch")

    def __init__(self, owner: "LockedSteadyBootWorkspace") -> None:
        self._owner = owner
        self._lock = owner._lock
        self._acquisition_epoch = owner._acquisition_epoch

    @property
    def attempt_id(self) -> str:
        # 该值只进入不对外暴露的旧引擎 metadata；steady wrapper 不读取它。
        return f"steady-{self._owner._boot_nonce}"

    @property
    def nonce(self) -> str:
        return self._owner._boot_nonce

    def _assert_live(self) -> None:
        self._owner._assert_resource_owner()

    def _release_exact_release_closures(
        self, resource: LockedExactReleaseClosures
    ) -> None:
        del resource

    def _close_exact_release_closures_public(
        self, resource: LockedExactReleaseClosures
    ) -> None:
        del resource
        raise DeploymentLockBusy(
            "steady 内部 release 引擎不得绕过 steady wrapper 关闭"
        )


class LockedSteadyReleaseClosures:
    """同一 steady epoch 的 active/prior 完整 release 现场闭包。

    该类型只复用已经验证的逐文件 open-instance 与递归 namespace monitor
    引擎；对外不暴露 transient attempt、journal、operation 或 start authority。
    """

    __slots__ = (
        "_persistence",
        "_lock",
        "_workspace",
        "_acquisition_epoch",
        "_facts",
        "_engine_workspace",
        "_engine",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady release closures 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady release closures 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        persistence: "LocalDeploymentPersistence",
        lock: CrashReleasedFileLock,
        workspace: "LockedSteadyBootWorkspace",
        facts: LockedSteadyPairStaticFacts,
        material: Mapping[str, object],
        _construction_token: object,
    ) -> None:
        if _construction_token is not _LOCKED_STEADY_RELEASE_CLOSURES_TOKEN:
            raise DeploymentLockBusy(
                "steady release closures 必须由 persistence façade 构造"
            )
        active = _release_ref(
            material.get("release"), label="steady closure active"
        )
        raw_prior = material.get("prior_release")
        prior = (
            None
            if raw_prior is None
            else _release_ref(raw_prior, label="steady closure prior")
        )
        if prior is not None and active == prior:
            raise RetentionPlanningError(
                "steady closure active/prior 必须是不同 release"
            )
        object.__setattr__(self, "_sealed", False)
        self._persistence = persistence
        self._lock = lock
        self._workspace = workspace
        self._acquisition_epoch = workspace._acquisition_epoch
        self._facts = facts
        self._engine_workspace = _SteadyReleaseClosureWorkspaceAdapter(workspace)
        self._engine = LockedExactReleaseClosures(
            persistence=persistence,
            lock=lock,
            workspace=self._engine_workspace,  # type: ignore[arg-type]
            operation="steady_boot",
            state_identity_sha256=str(material["state_identity_sha256"]),
            planned_compatibility_sha256=str(
                material["retention_aggregate_sha256"]
            ),
            role_references=(
                (("candidate", active),)
                if prior is None
                else (("candidate", active), ("prior", prior))
            ),
            _construction_token=_LOCKED_EXACT_RELEASE_CLOSURES_TOKEN,
        )
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError(
            "steady release closures are process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @staticmethod
    def _clone_json(value: object) -> object:
        return json.loads(_identity.canonical_bytes(value).decode("utf-8"))

    def _assert_live(self) -> Mapping[str, object]:
        self._workspace._assert_live()
        if (
            self._workspace._lock is not self._lock
            or self._workspace._acquisition_epoch is not self._acquisition_epoch
            or self._facts._persistence is not self._persistence
            or self._facts._lock is not self._lock
            or self._facts._workspace is not self._workspace
            or self._facts._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "steady release closures authority/workspace/epoch 漂移"
            )
        material = self._facts._assert_live()
        self._engine._assert_live()
        metadata = self._engine.metadata()
        roles = metadata.get("roles")
        candidate = roles.get("candidate") if isinstance(roles, Mapping) else None
        prior = roles.get("prior") if isinstance(roles, Mapping) else None
        active_ref = _release_ref(
            material.get("release"), label="steady closure live active"
        )
        raw_prior_ref = material.get("prior_release")
        prior_ref = (
            None
            if raw_prior_ref is None
            else _release_ref(
                raw_prior_ref, label="steady closure live prior"
            )
        )
        role_checks = [(candidate, active_ref, "active")]
        if prior_ref is not None:
            role_checks.append((prior, prior_ref, "prior"))
        elif prior is not None:
            raise RetentionPlanningError(
                "single-release steady closure 出现 prior metadata"
            )
        for role_metadata, reference, label in role_checks:
            if (
                not isinstance(role_metadata, Mapping)
                or role_metadata.get("release_id") != reference["release_id"]
                or role_metadata.get("manifest_sha256")
                != reference["manifest_sha256"]
            ):
                raise RetentionPlanningError(
                    f"steady {label} static/live closure 不一致"
                )
        return material

    @property
    def scope(self) -> str:
        self._assert_live()
        return _STEADY_RELEASE_CLOSURES_SCOPE

    @property
    def authority_kind(self) -> str:
        return str(self._assert_live()["authority_kind"])

    @property
    def runtime_state_kind(self) -> str:
        return str(self._assert_live()["runtime_state_kind"])

    @property
    def boot_nonce(self) -> str:
        return str(self._assert_live()["boot_nonce"])

    @property
    def state_identity_sha256(self) -> str:
        return str(self._assert_live()["state_identity_sha256"])

    @property
    def retention_aggregate_sha256(self) -> str:
        return str(self._assert_live()["retention_aggregate_sha256"])

    @property
    def roles(self) -> tuple[str, ...]:
        material = self._assert_live()
        return (
            ("active",)
            if material["prior_release"] is None
            else ("active", "prior")
        )

    def metadata(self) -> Mapping[str, object]:
        material = self._assert_live()
        engine = self._engine.metadata()
        roles = engine["roles"]
        if not isinstance(roles, Mapping):
            raise RetentionPlanningError("steady release metadata roles 漂移")
        value = {
            "scope": _STEADY_RELEASE_CLOSURES_SCOPE,
            "authority_kind": material["authority_kind"],
            "runtime_state_kind": material["runtime_state_kind"],
            "boot_nonce": material["boot_nonce"],
            "state_identity_sha256": material["state_identity_sha256"],
            "retention_aggregate_sha256": material[
                "retention_aggregate_sha256"
            ],
            "roles": {
                "active": roles["candidate"],
                "prior": roles["prior"],
            },
        }
        cloned = self._clone_json(value)
        if type(cloned) is not dict:
            raise RetentionPlanningError("steady release metadata clone 漂移")
        return cloned

    @staticmethod
    def _engine_role(role: str) -> str:
        if type(role) is not str or role not in {"active", "prior"}:
            raise UnsafeLocalPath("steady release role 只允许 active/prior")
        return "candidate" if role == "active" else "prior"

    def read_manifest(self, role: str) -> Mapping[str, object]:
        self._assert_live()
        return self._engine.read_manifest(self._engine_role(role))

    def read_migration(self, role: str, migration: str) -> bytes:
        self._assert_live()
        return self._engine.read_migration(self._engine_role(role), migration)

    def checkpoint_unchanged(self) -> None:
        # release namespace 漂移必须先让底层 open-instance 能力单调进入 revoked；
        # 若先重读 static facts，inventory 漂移会提前抛错并把底层留在 live，随后
        # workspace close 还会重复一次失败 checkpoint，无法机械收束资源。
        self._workspace._assert_live()
        self._engine.checkpoint_unchanged()
        self._assert_live()

    def _acquire(self) -> None:
        self._engine._acquire()
        self._assert_live()

    def _close_from_workspace(self, *, _close_token: object) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise DeploymentLockBusy(
                "steady release closure close authority 不匹配"
            )
        self._engine._close_from_workspace(
            _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN
        )
        self._workspace._release_steady_release_closures(self)

    def close(self) -> None:
        if self._engine._state == "closed":
            return
        self._workspace._close_steady_release_closures_public(self)

    def __enter__(self) -> "LockedSteadyReleaseClosures":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedAttemptWorkspace:
    """只在同一 B2 lock owner 下操作的 attempt-local bound workspace。"""

    def __init__(
        self,
        *,
        safe_root: _SafeRoot,
        lock: CrashReleasedFileLock,
        authority_token: object,
        acquisition_epoch: _LockAcquisitionEpoch,
        attempt_id: str,
        nonce: str,
        workspace_path: Path,
        guards: Sequence[_BoundDirectory],
        _construction_token: object,
    ):
        if _construction_token is not _ATTEMPT_WORKSPACE_TOKEN:
            raise UnsafeLocalPath("attempt workspace 必须由 persistence 构造")
        self._safe_root = safe_root
        self._lock = lock
        self._authority_token = authority_token
        self._acquisition_epoch = acquisition_epoch
        self._attempt_id = attempt_id
        self._nonce = nonce
        self._path = workspace_path
        self._guards: list[_BoundDirectory] = list(guards)
        self._directories: dict[tuple[str, ...], _BoundDirectory] = {
            (): self._guards[-1]
        }
        self._pins: set[PinnedSqliteSet] = set()
        self._open_files: dict[LockedNewFile, int] = {}
        self._state_sources: set[LockedStateSqliteSource] = set()
        self._exact_release_closures: set[LockedExactReleaseClosures] = set()
        self._windows_scm_process_handle_tracking: set[
            LockedWindowsScmProcessHandleTracking
        ] = set()
        self._windows_writer_lease_handle_tracking: set[
            LockedWindowsWriterLeaseHandleTracking
        ] = set()
        self._mutable_canary_sqlite_sets: set[
            LockedMutableCanarySqliteSet
        ] = set()
        self._runtime_canary_inputs: set[object] = set()
        self._runtime_canary_role: str | None = None
        self._state = "live"

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    @property
    def nonce(self) -> str:
        return self._nonce

    def _assert_live(self) -> None:
        if self._state != "live":
            raise UnsafeLocalPath("attempt workspace 不再处于 live 状态")
        self._lock._assert_epoch_held(
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )

    def _assert_close_owner(self) -> None:
        self._lock._assert_epoch_owner(
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )

    def _target(self, parts: Sequence[str]) -> Path:
        return self._path.joinpath(*parts)

    def _preflight_parts(
        self,
        parts: tuple[str, ...],
        *,
        expected_kind: str | None,
        allow_absent: bool,
    ) -> os.stat_result | None:
        if expected_kind not in {None, "file", "directory"}:
            raise UnsafeLocalPath("expected_kind 只允许 file/directory/None")
        metadata = self._safe_root.preflight(
            self._target(parts),
            expected_kind=expected_kind,
            allow_absent=allow_absent,
        )
        if (
            metadata is not None
            and stat.S_ISREG(metadata.st_mode)
            and getattr(metadata, "st_nlink", 1) != 1
        ):
            raise UnsafeLocalPath("attempt workspace 文件不得是 hardlink")
        return metadata

    def _parts(self, relative: object, *, label: str) -> tuple[str, ...]:
        parts = _closed_relative_parts(relative, label=label)
        if parts == (_ATTEMPT_WORKSPACE_BINDING,):
            raise UnsafeLocalPath("attempt workspace binding 是保留文件")
        return parts

    def _bind_runtime_canary_layout(
        self,
        authorization: LockedExactTransientStartAuthorization,
    ) -> None:
        """从同 epoch transient authorization 建立唯一 role-local 布局。"""

        self._assert_live()
        if type(authorization) is not LockedExactTransientStartAuthorization:
            raise DeploymentLockBusy(
                "runtime canary layout 必须绑定同一 transient authorization epoch"
            )
        try:
            same_epoch = (
                authorization._workspace is self
                and authorization._acquisition_epoch is self._acquisition_epoch
            )
            authorization._assert_live()
        except (AttributeError, DeploymentLockBusy, DeploymentJournalError) as error:
            raise DeploymentLockBusy(
                "runtime canary layout transient authorization 不可用"
            ) from error
        if not same_epoch:
            raise DeploymentLockBusy(
                "runtime canary layout 必须绑定同一 transient authorization epoch"
            )
        role = authorization.role
        if role not in {"candidate", "prior", "baseline"}:
            raise DeploymentJournalError("runtime canary role 不属于固定枚举")
        if self._runtime_canary_role is not None:
            raise DeploymentLockBusy("attempt workspace 已绑定 runtime canary role")
        base = f"runtime-canary/{role}"
        self.create_exact_directory(base)
        self.create_exact_directory(f"{base}/state")
        self.create_exact_directory(f"{base}/tmp")
        base_names = {
            entry.name for entry in os.scandir(self._target(("runtime-canary", role)))
        }
        state_names = {
            entry.name
            for entry in os.scandir(
                self._target(("runtime-canary", role, "state"))
            )
        }
        tmp_names = {
            entry.name
            for entry in os.scandir(
                self._target(("runtime-canary", role, "tmp"))
            )
        }
        if base_names != {"state", "tmp"} or state_names or tmp_names:
            raise UnsafeLocalPath(
                "runtime canary 初始布局存在 request/result/sidecar/未知成员"
            )
        self._runtime_canary_role = role

    def _mutable_canary_relative_parts(self, database: str) -> tuple[str, ...]:
        self._assert_live()
        role = self._runtime_canary_role
        if role not in {"candidate", "prior", "baseline"}:
            raise DeploymentLockBusy("runtime canary layout 尚未绑定")
        filename = _STATE_SQLITE_DATABASES[database]
        return ("runtime-canary", role, "state", filename)

    def _expected_mutable_canary_member_names(
        self,
        parent_parts: tuple[str, ...],
    ) -> set[str]:
        return {
            resource._relative_parts[-1]
            for resource in self._mutable_canary_sqlite_sets
            if resource._relative_parts[:-1] == parent_parts
            and resource._state != "closed"
        }

    def _bind_existing_directory(
        self, parts: tuple[str, ...]
    ) -> _BoundDirectory:
        guard = self._directories.get(parts)
        if guard is not None:
            return guard
        self._preflight_parts(
            parts, expected_kind="directory", allow_absent=False
        )
        guard = _BoundDirectory(self._safe_root, self._target(parts))
        guard.__enter__()
        self._guards.append(guard)
        self._directories[parts] = guard
        return guard

    def _parent_guard(self, parts: tuple[str, ...]) -> _BoundDirectory:
        parent_parts = parts[:-1]
        for depth in range(1, len(parent_parts) + 1):
            self._bind_existing_directory(parent_parts[:depth])
        return self._directories[parent_parts]

    def create_exact_directory(self, relative: str) -> None:
        self._assert_live()
        parts = self._parts(relative, label="attempt directory")
        for depth in range(1, len(parts) + 1):
            current = parts[:depth]
            observed = self._preflight_parts(
                current, expected_kind="directory", allow_absent=True
            )
            if observed is None:
                parent = self._parent_guard(current)
                if self._preflight_parts(
                    current, expected_kind="directory", allow_absent=True
                ) is not None:
                    raise UnsafeLocalPath("attempt directory mkdir 前出现第三值")
                try:
                    parent.mkdir(current[-1], 0o700)
                    parent.flush()
                except OSError as error:
                    raise UnsafeLocalPath("无法排他创建 attempt directory") from error
            self._preflight_parts(
                current, expected_kind="directory", allow_absent=False
            )
            self._bind_existing_directory(current)

    def preflight(
        self,
        relative: str,
        *,
        expected_kind: str | None = None,
        allow_absent: bool = True,
    ) -> os.stat_result | None:
        self._assert_live()
        parts = self._parts(relative, label="attempt target")
        return self._preflight_parts(
            parts, expected_kind=expected_kind, allow_absent=allow_absent
        )

    def open_new_file(self, relative: str) -> LockedNewFile:
        self._assert_live()
        parts = self._parts(relative, label="attempt file")
        parent = self._parent_guard(parts)
        if self._preflight_parts(
            parts, expected_kind="file", allow_absent=True
        ) is not None:
            raise UnsafeLocalPath("attempt file 已存在")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= (
            getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_SYNC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            descriptor = parent.open_file(parts[-1], flags, 0o600)
        except OSError as error:
            raise UnsafeLocalPath("无法排他创建 attempt file") from error
        try:
            opened = os.fstat(descriptor)
            observed = self._preflight_parts(
                parts, expected_kind="file", allow_absent=False
            )
            if (
                observed is None
                or not _same_file_identity(opened, observed)
                or not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or getattr(opened, "st_nlink", 1) != 1
            ):
                raise UnsafeLocalPath("attempt file open-handle 身份漂移")
            # 内容 durability 仍由持有者在写入后 fsync；这里先保证 exclusive-create
            # 的目录项不会只停留在 POSIX directory cache 中。
            parent.flush()
            opened_file = LockedNewFile(
                workspace=self,
                initial=opened,
                _construction_token=_LOCKED_NEW_FILE_TOKEN,
            )
            self._open_files[opened_file] = descriptor
            descriptor = None
            return opened_file
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise

    def atomic_replace(self, relative: str, raw: bytes) -> str:
        self._assert_live()
        if not isinstance(raw, bytes):
            raise UnsafeLocalPath("atomic_replace payload 必须是 bytes")
        parts = self._parts(relative, label="attempt atomic target")
        parent = self._parent_guard(parts)
        self._preflight_parts(parts, expected_kind="file", allow_absent=True)
        temporary_name = f".{parts[-1]}.{uuid.uuid4().hex}.tmp"
        temporary_parts = (*parts[:-1], temporary_name)
        self._safe_root.preflight(
            self._target(temporary_parts), expected_kind="file", allow_absent=True
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= (
            getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_SYNC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        descriptor: int | None = None
        try:
            descriptor = parent.open_file(temporary_name, flags, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short attempt atomic write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            parent.replace_from(
                parent,
                source_name=temporary_name,
                destination_name=parts[-1],
            )
            observed = self._preflight_parts(
                parts, expected_kind="file", allow_absent=False
            )
            if observed is None or getattr(observed, "st_nlink", 1) != 1:
                raise UnsafeLocalPath("atomic_replace 目标不是普通独占文件")
            final_descriptor = parent.open_file(
                parts[-1], os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                os.fsync(final_descriptor)
            finally:
                os.close(final_descriptor)
            parent.flush()
        except OSError as error:
            raise UnsafeLocalPath("attempt atomic_replace 失败") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                if self._safe_root.preflight(
                    self._target(temporary_parts),
                    expected_kind="file",
                    allow_absent=True,
                ) is not None:
                    parent.unlink(temporary_name)
            except OSError:
                pass
        return hashlib.sha256(raw).hexdigest()

    def pin_sqlite_set(self, relative: str) -> PinnedSqliteSet:
        self._assert_live()
        parts = self._parts(relative, label="SQLite main")
        if not parts[-1].endswith(".sqlite3"):
            raise UnsafeLocalPath("SQLite main 必须使用 .sqlite3 文件名")
        parent = self._parent_guard(parts)
        members: list[_PinnedSqliteMember] = []
        try:
            for label, suffix in (("main", ""), ("wal", "-wal"), ("shm", "-shm")):
                member_parts = (*parts[:-1], parts[-1] + suffix)
                observed = self._preflight_parts(
                    member_parts, expected_kind="file", allow_absent=True
                )
                if observed is None:
                    if label == "main":
                        raise UnsafeLocalPath("SQLite main 不存在")
                    members.append(
                        _PinnedSqliteMember(label, member_parts, None, None)
                    )
                    continue
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                descriptor = parent.open_file(member_parts[-1], flags)
                opened = os.fstat(descriptor)
                confirmed = self._preflight_parts(
                    member_parts, expected_kind="file", allow_absent=False
                )
                if (
                    confirmed is None
                    or not _same_file_identity(observed, opened)
                    or not _same_file_identity(opened, confirmed)
                    or not stat.S_ISREG(opened.st_mode)
                    or _is_reparse(opened)
                    or getattr(opened, "st_nlink", 1) != 1
                ):
                    os.close(descriptor)
                    raise UnsafeLocalPath("SQLite member open-handle 身份漂移")
                members.append(
                    _PinnedSqliteMember(label, member_parts, descriptor, opened)
                )
        except Exception:
            for member in members:
                if member.descriptor is not None:
                    os.close(member.descriptor)
            raise
        pinned = PinnedSqliteSet(
            workspace=self,
            members=tuple(members),
            _construction_token=_PINNED_SQLITE_TOKEN,
        )
        self._pins.add(pinned)
        return pinned

    def _release_pin(self, pinned: PinnedSqliteSet) -> None:
        if not pinned._closed or any(
            member.descriptor is not None for member in pinned._members
        ):
            raise UnsafeLocalPath("SQLite pin 未机械闭合，不得解除 tracking")
        if pinned not in self._pins:
            raise UnsafeLocalPath("SQLite pin 不属于当前 workspace")
        self._pins.remove(pinned)

    def _close_pin_public(self, pinned: PinnedSqliteSet) -> None:
        self._assert_live()
        try:
            pinned._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            self._state = "closing"
            raise

    def _open_file_descriptor(self, opened_file: LockedNewFile) -> int:
        self._assert_live()
        descriptor = self._open_files.get(opened_file)
        if descriptor is None:
            raise UnsafeLocalPath("LockedNewFile 不属于当前 workspace")
        return descriptor

    def _open_file_descriptor_for_close(
        self,
        opened_file: LockedNewFile,
        *,
        _close_token: object,
    ) -> int:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("LockedNewFile close authority 不匹配")
        descriptor = self._open_files.get(opened_file)
        if descriptor is None:
            raise UnsafeLocalPath("LockedNewFile 不属于当前 workspace")
        return descriptor

    def _release_open_file_after_proven_close(
        self,
        opened_file: LockedNewFile,
        *,
        descriptor: int,
        _close_token: object,
    ) -> None:
        if _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN:
            raise UnsafeLocalPath("LockedNewFile close authority 不匹配")
        if self._open_files.get(opened_file) != descriptor:
            raise UnsafeLocalPath("LockedNewFile descriptor tracking 漂移")
        self._open_files.pop(opened_file)

    def _close_file_public(self, opened_file: LockedNewFile) -> None:
        self._assert_live()
        try:
            opened_file._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            self._state = "closing"
            raise

    def _register_state_source(self, source: LockedStateSqliteSource) -> None:
        self._assert_live()
        if source._workspace is not self or source._lock is not self._lock:
            raise DeploymentLockBusy("state SQLite source 不属于当前 workspace/lock")
        self._state_sources.add(source)

    def _release_state_source(self, source: LockedStateSqliteSource) -> None:
        if source._state != "closed":
            raise UnsafeLocalPath("state SQLite source 未机械闭合")
        if source not in self._state_sources:
            raise UnsafeLocalPath("state SQLite source 未登记")
        self._state_sources.remove(source)

    def _mark_source_closing(self) -> None:
        if self._state != "closed":
            self._state = "closing"

    def _close_state_source_public(self, source: LockedStateSqliteSource) -> None:
        self._assert_live()
        try:
            source._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            self._state = "closing"
            raise

    def _register_exact_release_closures(
        self, closures: LockedExactReleaseClosures
    ) -> None:
        self._assert_live()
        if closures._workspace is not self or closures._lock is not self._lock:
            raise DeploymentLockBusy(
                "exact release closures 不属于当前 workspace/lock"
            )
        self._exact_release_closures.add(closures)

    def _release_exact_release_closures(
        self, closures: LockedExactReleaseClosures
    ) -> None:
        if closures._state != "closed":
            raise UnsafeLocalPath("exact release closures 未机械闭合")
        if closures not in self._exact_release_closures:
            raise UnsafeLocalPath("exact release closures 未登记")
        self._exact_release_closures.remove(closures)

    def _close_exact_release_closures_public(
        self, closures: LockedExactReleaseClosures
    ) -> None:
        self._assert_live()
        try:
            closures._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            self._state = "closing"
            raise

    def _register_windows_scm_process_handle_tracking(
        self, tracking: LockedWindowsScmProcessHandleTracking
    ) -> None:
        self._assert_live()
        if (
            type(tracking) is not LockedWindowsScmProcessHandleTracking
            or tracking._workspace is not self
            or tracking._lock is not self._lock
            or tracking._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "Windows SCM/process handle tracking 不属于当前 workspace/epoch"
            )
        if self._windows_scm_process_handle_tracking:
            raise DeploymentLockBusy(
                "同一 attempt workspace 只允许一个 live Windows observation tracking"
            )
        self._windows_scm_process_handle_tracking.add(tracking)

    def _release_windows_scm_process_handle_tracking(
        self, tracking: LockedWindowsScmProcessHandleTracking
    ) -> None:
        if tracking._state != "closed":
            raise UnsafeLocalPath(
                "Windows SCM/process handle tracking 未机械闭合"
            )
        if tracking not in self._windows_scm_process_handle_tracking:
            raise UnsafeLocalPath(
                "Windows SCM/process handle tracking 未登记"
            )
        self._windows_scm_process_handle_tracking.remove(tracking)

    def _close_windows_scm_process_handle_tracking_public(
        self, tracking: LockedWindowsScmProcessHandleTracking
    ) -> None:
        self._assert_live()
        if any(
            writer_tracking._scm_tracking is tracking
            for writer_tracking in self._windows_writer_lease_handle_tracking
        ):
            raise DeploymentLockBusy(
                "writer lease tracking live 时不得先关闭 SCM tracking"
            )
        try:
            tracking._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            if tracking._state != "owner_crash_only":
                self._state = "closing"
            raise

    def _register_windows_writer_lease_handle_tracking(
        self, tracking: LockedWindowsWriterLeaseHandleTracking
    ) -> None:
        self._assert_live()
        if (
            type(tracking) is not LockedWindowsWriterLeaseHandleTracking
            or tracking._workspace is not self
            or tracking._lock is not self._lock
            or tracking._acquisition_epoch is not self._acquisition_epoch
            or tracking._scm_tracking
            not in self._windows_scm_process_handle_tracking
        ):
            raise DeploymentLockBusy(
                "Windows writer lease tracking 不属于当前 workspace/SCM epoch"
            )
        if self._windows_writer_lease_handle_tracking:
            raise DeploymentLockBusy(
                "同一 attempt workspace 只允许一个 live writer lease tracking"
            )
        self._windows_writer_lease_handle_tracking.add(tracking)

    def _release_windows_writer_lease_handle_tracking(
        self, tracking: LockedWindowsWriterLeaseHandleTracking
    ) -> None:
        if tracking._state != "closed":
            raise UnsafeLocalPath("Windows writer lease tracking 未机械闭合")
        if tracking not in self._windows_writer_lease_handle_tracking:
            raise UnsafeLocalPath("Windows writer lease tracking 未登记")
        self._windows_writer_lease_handle_tracking.remove(tracking)

    def _close_windows_writer_lease_handle_tracking_public(
        self, tracking: LockedWindowsWriterLeaseHandleTracking
    ) -> None:
        self._assert_live()
        try:
            tracking._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            if tracking._state != "owner_crash_only":
                self._state = "closing"
            raise

    def _register_mutable_canary_sqlite_set(
        self, resource: LockedMutableCanarySqliteSet
    ) -> None:
        self._assert_live()
        if (
            type(resource) is not LockedMutableCanarySqliteSet
            or resource._workspace is not self
            or resource._lock is not self._lock
            or resource._acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "mutable canary SQLite set 不属于当前 workspace/epoch"
            )
        if any(
            current._database == resource._database
            for current in self._mutable_canary_sqlite_sets
        ):
            raise DeploymentLockBusy(
                "同一 runtime canary database 只允许一个 live mutable set"
            )
        self._mutable_canary_sqlite_sets.add(resource)

    def _register_runtime_canary_input(self, resource: object) -> None:
        """局部导入 e.4.1 exact type，避免 persistence 顶层反向依赖。"""

        self._assert_live()
        from .local_exact_runtime_canary_input import (
            LockedExactRuntimeCanaryInput,
        )

        if (
            type(resource) is not LockedExactRuntimeCanaryInput
            or resource._workspace is not self
            or resource._lock is not self._lock
            or resource._state != "live"
        ):
            raise DeploymentLockBusy(
                "runtime canary input 不属于当前 workspace/epoch"
            )
        if self._runtime_canary_inputs:
            raise DeploymentLockBusy("attempt workspace 只允许一个 live canary input")
        self._runtime_canary_inputs.add(resource)

    def _release_runtime_canary_input(self, resource: object) -> None:
        if getattr(resource, "_state", None) != "closed":
            raise UnsafeLocalPath("runtime canary input 未机械闭合")
        if resource not in self._runtime_canary_inputs:
            raise UnsafeLocalPath("runtime canary input 未登记")
        self._runtime_canary_inputs.remove(resource)

    def _close_runtime_canary_input_public(self, resource: object) -> None:
        self._assert_live()
        if resource not in self._runtime_canary_inputs:
            raise UnsafeLocalPath("runtime canary input 不属于当前 workspace")
        resource._close_from_workspace(self)

    def _release_mutable_canary_sqlite_set(
        self, resource: LockedMutableCanarySqliteSet
    ) -> None:
        if resource._state != "closed":
            raise UnsafeLocalPath("mutable canary SQLite set 未机械闭合")
        if resource not in self._mutable_canary_sqlite_sets:
            raise UnsafeLocalPath("mutable canary SQLite set 未登记")
        self._mutable_canary_sqlite_sets.remove(resource)

    def _close_mutable_canary_sqlite_set_public(
        self, resource: LockedMutableCanarySqliteSet
    ) -> None:
        self._assert_live()
        try:
            resource._close_from_workspace(
                _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
            )
        except BaseException:
            if resource._state != "owner_crash_only":
                self._state = "closing"
            raise

    def remove_exact_transient(self, relative: str) -> bool:
        self._assert_live()
        parts = self._parts(relative, label="attempt removal target")
        for resource in self._mutable_canary_sqlite_sets:
            if resource._relative_parts == parts:
                raise UnsafeLocalPath(
                    "不得删除仍由 mutable canary open instance 守护的 main"
                )
        for pinned in self._pins:
            for member in pinned._members:
                if member.relative_parts == parts:
                    raise UnsafeLocalPath("不得删除仍被 pin 的 SQLite member")
        observed = self._preflight_parts(
            parts, expected_kind=None, allow_absent=True
        )
        if observed is None:
            return False
        parent = self._parent_guard(parts)
        try:
            if stat.S_ISREG(observed.st_mode):
                if getattr(observed, "st_nlink", 1) != 1:
                    raise UnsafeLocalPath("不得删除 hardlink transient")
                parent.unlink(parts[-1])
            elif stat.S_ISDIR(observed.st_mode):
                descendants = [
                    key for key in self._directories if key[: len(parts)] == parts
                ]
                if any(key != parts for key in descendants):
                    raise UnsafeLocalPath("不得删除仍绑定子目录的 transient")
                guard = self._directories.get(parts)
                if guard is not None:
                    try:
                        guard.__exit__(None, None, None)
                    except BaseException:
                        self._state = "closing"
                        raise
                    if not guard._fully_closed():
                        self._state = "closing"
                        raise UnsafeLocalPath(
                            "transient directory guard 未机械闭合"
                        )
                    self._directories.pop(parts, None)
                    self._guards.remove(guard)
                try:
                    parent.rmdir(parts[-1])
                except Exception:
                    self._bind_existing_directory(parts)
                    raise
            else:
                raise UnsafeLocalPath("transient 只允许普通文件或空目录")
            parent.flush()
        except OSError as error:
            raise UnsafeLocalPath("无法删除 exact transient") from error
        if self._preflight_parts(
            parts, expected_kind=None, allow_absent=True
        ) is not None:
            raise UnsafeLocalPath("transient 删除后仍存在")
        return True

    def _close_resources(self) -> None:
        if self._state != "closing":
            raise UnsafeLocalPath("workspace 只能从 closing 状态闭合资源")
        close_error: BaseException | None = None
        # input 本身无 raw handle，但必须先撤销，随后才允许它引用的 guard/view
        # 按各自 state owner 闭合。
        for resource in tuple(self._runtime_canary_inputs):
            try:
                resource._close_from_workspace(self)
            except BaseException as error:
                if close_error is None:
                    close_error = error
        # writer lease tracking 借用 SCM child process handle，必须最先关闭；
        # SCM observation handle 又依赖 live input/closure，必须先于 closure 关闭。
        for tracking in tuple(self._windows_writer_lease_handle_tracking):
            try:
                tracking._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for tracking in tuple(self._windows_scm_process_handle_tracking):
            try:
                tracking._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for resource in tuple(self._mutable_canary_sqlite_sets):
            try:
                resource._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for closures in tuple(self._exact_release_closures):
            try:
                closures._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for source in tuple(self._state_sources):
            try:
                source._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for opened_file in tuple(self._open_files):
            try:
                opened_file._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for pinned in tuple(self._pins):
            try:
                pinned._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as error:
                if close_error is None:
                    close_error = error
        for guard in tuple(reversed(self._guards)):
            try:
                guard.__exit__(None, None, None)
            except BaseException as error:
                if close_error is None:
                    close_error = error
                continue
            if not guard._fully_closed():
                if close_error is None:
                    close_error = UnsafeLocalPath(
                        "workspace directory guard 未机械闭合"
                    )
                continue
            self._guards.remove(guard)
            for parts, registered in tuple(self._directories.items()):
                if registered is guard:
                    self._directories.pop(parts, None)
        if (
            close_error is not None
            or self._runtime_canary_inputs
            or self._windows_writer_lease_handle_tracking
            or self._windows_scm_process_handle_tracking
            or self._mutable_canary_sqlite_sets
            or self._exact_release_closures
            or self._state_sources
            or self._open_files
            or self._pins
            or self._guards
            or self._directories
        ):
            raise LocalDeploymentPersistenceError(
                "attempt workspace resource 关闭失败"
            ) from close_error

    def _close_and_unregister(self) -> None:
        if self._state == "closed":
            return
        if self._state == "live":
            self._state = "closing"
        self._close_resources()
        self._lock._unregister_workspace(
            self,
            authority_token=self._authority_token,
            acquisition_epoch=self._acquisition_epoch,
        )
        self._state = "closed"

    def _close_for_lock_release(
        self,
        *,
        lock: CrashReleasedFileLock,
        acquisition_epoch: _LockAcquisitionEpoch,
        _close_token: object,
    ) -> None:
        if (
            _close_token is not _WORKSPACE_RESOURCE_CLOSE_TOKEN
            or lock is not self._lock
            or acquisition_epoch is not self._acquisition_epoch
        ):
            raise DeploymentLockBusy("attempt workspace release authority 不匹配")
        self._assert_close_owner()
        self._close_and_unregister()

    def close(self) -> None:
        if self._state == "closed":
            return
        self._assert_close_owner()
        self._close_and_unregister()

    def __enter__(self) -> "LockedAttemptWorkspace":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class _CanonicalCasAuthority:
    def __init__(
        self,
        *,
        path: Path,
        label: str,
        validator: Callable[[object], Mapping[str, object]],
        safe_root: _SafeRoot,
        temporary_directory: Path,
        authority_token: object,
    ):
        self._path = path
        self._label = label
        self._validator = validator
        self._safe_root = safe_root
        self._temporary_directory = temporary_directory
        self._authority_token = authority_token

    def read(self) -> CanonicalJsonRecord | None:
        return _canonical_read(
            self._path,
            safe_root=self._safe_root,
            validator=self._validator,
            label=self._label,
        )

    def compare_and_swap(
        self,
        *,
        lock: CrashReleasedFileLock,
        expected: object | None,
        desired: object,
        target_parent: _BoundDirectory | None = None,
        temporary_parent: _BoundDirectory | None = None,
    ) -> CompareAndSwapResult:
        lock.assert_held(authority_token=self._authority_token)
        try:
            desired_value = self._validator(desired)
            expected_value = None if expected is None else self._validator(expected)
        except Exception as error:
            raise LocalDeploymentPersistenceError(
                f"{self._label} CAS 输入不满足 schema"
            ) from error
        desired_raw = _identity.canonical_bytes(desired_value)
        expected_raw = (
            None if expected_value is None else _identity.canonical_bytes(expected_value)
        )
        observed = self.read()  # 锁内重读，不信任锁外快照。
        if observed is not None and observed.raw == desired_raw:
            confirmed = self.read()
            if confirmed is None or confirmed.raw != desired_raw:
                raise CompareAndSwapConflict(f"{self._label} desired 重读漂移")
            return CompareAndSwapResult("already_desired", confirmed.sha256)
        observed_raw = None if observed is None else observed.raw
        if observed_raw != expected_raw:
            raise CompareAndSwapConflict(
                f"{self._label} 出现 expected/desired 之外的第三值"
            )
        if (target_parent is None) != (temporary_parent is None):
            raise UnsafeLocalPath(
                f"{self._label} CAS bound parent 必须成对提供"
            )
        if target_parent is None or temporary_parent is None:
            _write_through_replace(
                self._path,
                desired_raw,
                safe_root=self._safe_root,
                temporary_directory=self._temporary_directory,
            )
        else:
            _write_through_replace_bound(
                self._path,
                desired_raw,
                safe_root=self._safe_root,
                temporary_directory=self._temporary_directory,
                target_parent=target_parent,
                temporary_parent=temporary_parent,
            )
        confirmed = self.read()
        if confirmed is None or confirmed.raw != desired_raw:
            raise CompareAndSwapConflict(f"{self._label} replace 后不是 desired")
        return CompareAndSwapResult("swapped", confirmed.sha256)

    def compare_and_delete(
        self,
        *,
        lock: CrashReleasedFileLock,
        expected: object,
        target_parent: _BoundDirectory | None = None,
    ) -> CompareAndSwapResult:
        """Delete one exact current document, idempotently reaching absent."""

        lock.assert_held(authority_token=self._authority_token)
        try:
            expected_value = self._validator(expected)
        except Exception as error:
            raise LocalDeploymentPersistenceError(
                f"{self._label} delete-CAS expected 不满足 schema"
            ) from error
        expected_raw = _identity.canonical_bytes(expected_value)
        observed = self.read()
        if observed is None:
            return CompareAndSwapResult(
                "already_desired", hashlib.sha256(b"absent").hexdigest()
            )
        if observed.raw != expected_raw:
            raise CompareAndSwapConflict(
                f"{self._label} delete-CAS 出现 expected/absent 之外的第三值"
            )
        owned_parent = None
        parent = target_parent
        if parent is None:
            owned_parent = _BoundDirectory(self._safe_root, self._path.parent)
            parent = owned_parent.__enter__()
        try:
            confirmed = self.read()
            if confirmed is None or confirmed.raw != expected_raw:
                raise CompareAndSwapConflict(
                    f"{self._label} delete-CAS guard 内漂移"
                )
            parent.unlink(self._path.name)
            parent.flush()
        finally:
            if owned_parent is not None:
                owned_parent.__exit__(None, None, None)
        if self.read() is not None:
            raise CompareAndSwapConflict(
                f"{self._label} delete-CAS 后未到达 absent"
            )
        return CompareAndSwapResult(
            "swapped", hashlib.sha256(b"absent").hexdigest()
        )


def _release_ref(value: object, *, label: str) -> Mapping[str, object]:
    try:
        active = _identity.validate_active_release(
            {"schema_version": _identity.ACTIVE_RELEASE_SCHEMA, "release": value}
        )
    except Exception as error:
        raise DeploymentJournalError(f"{label} 不是 exact release ref") from error
    return active["release"]


def _pair(
    value: object,
    *,
    label: str,
    allow_missing_active: bool,
    allow_missing_prior: bool,
) -> Mapping[str, object]:
    pair = _closed(value, {"active", "prior"}, label=label)
    active_value = pair["active"]
    if active_value is None:
        if not allow_missing_active or pair["prior"] is not None:
            raise DeploymentJournalError(f"{label} active 缺失语义非法")
        return pair
    active = _release_ref(active_value, label=f"{label}.active")
    prior_value = pair["prior"]
    if prior_value is None:
        if not allow_missing_prior:
            raise DeploymentJournalError(f"{label} 必须有唯一 prior")
        return pair
    prior = _release_ref(prior_value, label=f"{label}.prior")
    if (
        str(active["release_id"]).casefold()
        == str(prior["release_id"]).casefold()
        or active["manifest_sha256"] == prior["manifest_sha256"]
    ):
        raise DeploymentJournalError(f"{label} active/prior 必须不同")
    return pair


def _cleanup_target(value: object, *, label: str) -> Mapping[str, object]:
    """复用 B1 closed cleanup union，避免 B2 再发明第二套边界。"""

    try:
        # B1 validator 是 receipt-private，因此用最小 typed receipt 包装不可行；
        # 这里机械复制其 closed union，并在 retention 时再次验证真实 closure。
        target = _object(value, label=label)
        kind = target.get("kind")
        if kind == "release_closure":
            target = _closed(target, {"kind", "release", "closure_sha256"}, label=label)
            _release_ref(target["release"], label=f"{label}.release")
        elif kind in {"incoming", "partial"}:
            target = _closed(
                target,
                {"kind", "path", "payload_sha256", "closure_sha256"},
                label=label,
            )
            _sha256(target["payload_sha256"], label=f"{label}.payload_sha256")
        elif kind == "unreferenced_object":
            target = _closed(
                target,
                {"kind", "path", "object_sha256", "closure_sha256"},
                label=label,
            )
            _sha256(target["object_sha256"], label=f"{label}.object_sha256")
        else:
            raise DeploymentJournalError(f"{label}.kind 不支持")
        if kind != "release_closure":
            path = target["path"]
            if not isinstance(path, str) or str(PureWindowsPath(path)) != path:
                raise DeploymentJournalError(f"{label}.path 不是 exact Windows path")
            expected_root = (
                _identity.PRODUCTION_OBJECT_ROOT
                if kind == "unreferenced_object"
                else _identity.PRODUCTION_INCOMING_ROOT
            )
            if not path.startswith(str(expected_root) + "\\"):
                raise DeploymentJournalError(f"{label}.path 根大小写/字符不 canonical")
            try:
                relative = PureWindowsPath(path).relative_to(expected_root)
            except ValueError as error:
                raise DeploymentJournalError(f"{label}.path 越出批准子树") from error
            if not relative.parts or any(part in {".", ".."} for part in relative.parts):
                raise DeploymentJournalError(f"{label}.path 非 exact child")
            forbidden_windows = set('<>:"|?*')
            for part in relative.parts:
                normalized = unicodedata.normalize("NFKC", part)
                if (
                    normalized != part
                    or
                    part.endswith((".", " "))
                    or normalized.endswith((".", " "))
                    or any(character in forbidden_windows for character in normalized)
                    or normalized.split(".", 1)[0].casefold()
                    in _WINDOWS_DEVICE_NAMES
                ):
                    raise DeploymentJournalError(f"{label}.path 含 Windows 不安全组件")
            if kind in {"incoming", "partial"}:
                is_partial = PureWindowsPath(path).name.casefold().endswith(".partial")
                if (kind == "partial") != is_partial:
                    raise DeploymentJournalError(f"{label}.kind/path 不一致")
        _sha256(target["closure_sha256"], label=f"{label}.closure_sha256")
        return target
    except DeploymentJournalError:
        raise
    except Exception as error:
        raise DeploymentJournalError(f"{label} 不满足 cleanup union") from error


def _cleanup_sort_key(target: Mapping[str, object]) -> tuple[str, str, str]:
    path = (
        target["release"]["release_path"]
        if target["kind"] == "release_closure"
        else target["path"]
    )
    return str(target["kind"]), str(path).casefold(), _identity.identity_sha256(target)


_EVIDENCE_FIELDS = {
    "root_preflight_sha256",
    "state_compatibility_sha256",
    "prior_start_authorization_sha256",
    "prior_runtime_qualification_sha256",
    "pointer_cas_observation_sha256",
    "candidate_start_authorization_sha256",
    "candidate_runtime_qualification_sha256",
    "binding_cas_observation_sha256",
    "controller_verification_sha256",
    "cleanup_authorization_sha256",
    "cleanup_receipt_sha256",
    "write_set_sha256",
    "bootstrap_ingress_closed_sha256",
    "bootstrap_legacy_c_writer_fence_sha256",
    "failure_original_pointer_observation_sha256",
    "failure_original_binding_observation_sha256",
    "failure_original_service_observation_sha256",
    "failure_original_writer_fence_observation_sha256",
    "failure_state_identity_observation_sha256",
}


def _operation_phases(operation: str) -> tuple[str, ...]:
    return _BOOTSTRAP_PHASES if operation == "bootstrap_first_pair" else _ORDINARY_PHASES


def _expected_failed_phase(operation: str, revision: int) -> str:
    """Return the last legal non-terminal phase immediately before a failure."""

    phases = _operation_phases(operation)
    success_terminal_index = phases.index("terminal_receipt_committed")
    previous_index = revision - 1
    if previous_index < 0 or previous_index >= success_terminal_index:
        raise DeploymentJournalError(
            "failure terminal must immediately follow a legal non-terminal phase"
        )
    return phases[previous_index]


def _journal_is_closed(journal: Mapping[str, object]) -> bool:
    phase = journal["phase"]
    return phase == _FAILURE_PHASE or (
        phase == "terminal_receipt_committed"
        and journal["operation"] == "bootstrap_first_pair"
    ) or phase == "cleanup_receipt_committed"


def _assert_transient_authorization_phase_open(
    journal: Mapping[str, object],
) -> None:
    """瞬态启动输入只在 success/failure terminal 之前存活。"""

    operation = str(journal["operation"])
    phase = str(journal["phase"])
    if phase == _FAILURE_PHASE:
        raise DeploymentJournalError(
            "terminal journal 不得派生 transient start authorization"
        )
    phases = _operation_phases(operation)
    if phase not in phases or phases.index(phase) >= phases.index(
        "terminal_receipt_committed"
    ):
        raise DeploymentJournalError(
            "terminal journal 不得派生 transient start authorization"
        )


def _transient_start_authorization_evidence_field(role: object) -> str:
    if type(role) is not str or role not in {"prior", "candidate", "baseline"}:
        raise DeploymentJournalError("transient start authorization role 不支持")
    return (
        "prior_start_authorization_sha256"
        if role == "prior"
        else "candidate_start_authorization_sha256"
    )


def _transient_scm_start_plan_material(
    journal: Mapping[str, object],
    start: Mapping[str, object],
) -> Mapping[str, object]:
    """构造启动前即可确定、且不与 authorization hash 成环的 SCM 计划。"""

    role = start["role"]
    _transient_start_authorization_evidence_field(role)
    attempt = _identifier(journal["attempt"], label="SCM start plan attempt")
    nonce = _identifier(journal["nonce"], label="SCM start plan nonce")
    start_nonce = _identifier(
        start["start_nonce"], label="SCM start plan start nonce"
    )
    release = _release_ref(start["release"], label="SCM start plan release")
    state_plan = journal["state_plan"]
    if not isinstance(state_plan, Mapping):
        raise DeploymentJournalError("SCM start plan state_plan 类型漂移")
    state_identity_sha256 = _sha256(
        state_plan["state_identity_sha256"], label="SCM start plan state identity"
    )
    operation = str(journal["operation"])
    service_start_arguments = [
        "exact-runtime",
        "--deployment-attempt",
        attempt,
        "--deployment-nonce",
        nonce,
        "--deployment-operation",
        operation,
        "--deployment-role",
        str(role),
        "--start-nonce",
        start_nonce,
        "--release-id",
        str(release["release_id"]),
        "--manifest-sha256",
        str(release["manifest_sha256"]),
        "--state-identity-sha256",
        state_identity_sha256,
    ]
    child_argv = [
        _EXACT_SCM_CHILD_EXECUTABLE,
        "-I",
        "-B",
        "-X",
        "utf8",
        "-X",
        "pycache_prefix=" + _EXACT_SCM_PYCACHE_PARENT + "\\" + start_nonce,
        "-m",
        _EXACT_SCM_CHILD_MODULE,
        "--deployment-attempt",
        attempt,
        "--deployment-nonce",
        nonce,
        "--deployment-operation",
        operation,
        "--deployment-role",
        str(role),
        "--start-nonce",
        start_nonce,
        "--release-id",
        str(release["release_id"]),
        "--manifest-sha256",
        str(release["manifest_sha256"]),
        "--state-identity-sha256",
        state_identity_sha256,
    ]
    return {
        "schema_version": _EXACT_SCM_START_PLAN_SCHEMA,
        "scope": _EXACT_SCM_START_PLAN_SCOPE,
        "attempt": attempt,
        "nonce": nonce,
        "operation": operation,
        "role": role,
        "start_nonce": start_nonce,
        "state_identity_sha256": state_identity_sha256,
        "release": release,
        "service": {
            "service_name": _EXACT_SCM_SERVICE_NAME,
            "binary_path": _EXACT_SCM_HOST_EXECUTABLE,
            "python_class": _EXACT_SCM_PYTHON_CLASS,
            "start_type": "automatic",
            "start_arguments": service_start_arguments,
        },
        "child": {
            "executable": _EXACT_SCM_CHILD_EXECUTABLE,
            "module": _EXACT_SCM_CHILD_MODULE,
            "argv": child_argv,
        },
    }


def _transient_scm_start_plan_sha256(
    journal: Mapping[str, object],
    start: Mapping[str, object],
) -> str:
    return _identity.identity_sha256(
        _transient_scm_start_plan_material(journal, start)
    )


def _legacy_transient_scm_start_plan_sha256(
    journal: Mapping[str, object],
    start: Mapping[str, object],
) -> str:
    """Rebuild the sole pre-root-bundle SCM plan for closed-history replay."""

    material = dict(_transient_scm_start_plan_material(journal, start))
    service = dict(material["service"])
    service["binary_path"] = _LEGACY_EXACT_SCM_HOST_EXECUTABLE
    material["service"] = service
    return _identity.identity_sha256(material)


def _transient_start_authorization_material(
    journal: Mapping[str, object],
    start: Mapping[str, object],
) -> Mapping[str, object]:
    """构造唯一 canonical、closed 的 transient start authorization material。"""

    role = start["role"]
    _transient_start_authorization_evidence_field(role)
    authorization_phase = (
        "prior_start_authorized"
        if role == "prior"
        else "candidate_start_authorized"
    )
    state_plan = journal["state_plan"]
    if not isinstance(state_plan, Mapping):
        raise DeploymentJournalError("transient authorization state_plan 类型漂移")
    return {
        "schema_version": _EXACT_TRANSIENT_START_AUTHORIZATION_SCHEMA,
        "scope": _EXACT_TRANSIENT_START_AUTHORIZATION_SCOPE,
        "attempt": _identifier(
            journal["attempt"], label="transient authorization attempt"
        ),
        "nonce": _identifier(
            journal["nonce"], label="transient authorization nonce"
        ),
        "operation": str(journal["operation"]),
        "authorization_phase": authorization_phase,
        "role": role,
        "release": _release_ref(
            start["release"], label="transient authorization release"
        ),
        "start_nonce": _identifier(
            start["start_nonce"], label="transient authorization start nonce"
        ),
        "scm_identity_sha256": _sha256(
            start["scm_identity_sha256"],
            label="transient authorization SCM identity",
        ),
        "state_identity_sha256": _sha256(
            state_plan["state_identity_sha256"],
            label="transient authorization state identity",
        ),
    }


def _transient_start_authorization_sha256(
    journal: Mapping[str, object],
    start: Mapping[str, object],
) -> str:
    return _identity.identity_sha256(
        _transient_start_authorization_material(journal, start)
    )


def _forbid_self_reported_qualification(value: object) -> None:
    forbidden = {
        "started",
        "candidate_started",
        "service_started",
        "health",
        "healthy",
        "writer_fence",
        "writer_fenced",
        "qualified",
        "capability",
    }

    def walk(current: object) -> None:
        if isinstance(current, bool):
            raise DeploymentJournalError("journal 不接受调用者自报布尔资格")
        if isinstance(current, dict):
            for key, child in current.items():
                if key.casefold().replace("-", "_") in forbidden:
                    raise DeploymentJournalError("journal 含自报动态资格字段")
                walk(child)
        elif isinstance(current, list):
            for child in current:
                walk(child)

    walk(value)


def validate_deployment_journal(
    value: object,
    *,
    _allow_legacy_scm_plan: bool = False,
) -> Mapping[str, object]:
    """验证 closed ``qrh-deployment-attempt/v4`` revision。"""

    journal = _closed(
        value,
        {
            "schema_version",
            "attempt",
            "operation",
            "revision",
            "phase",
            "nonce",
            "timestamps",
            "previous_journal_sha256",
            "original_pair",
            "candidate",
            "target_pair",
            "pointer_cas",
            "binding_cas",
            "state_plan",
            "database_seals",
            "transient_start",
            "reserved_receipt_ids",
            "cleanup_targets",
            "evidence_hashes",
            "terminal_receipt",
            "journal_sha256",
        },
        label="deployment journal",
    )
    if journal["schema_version"] != DEPLOYMENT_ATTEMPT_SCHEMA:
        raise DeploymentJournalError("deployment journal schema version 不符")
    _forbid_self_reported_qualification(journal)
    _identifier(journal["attempt"], label="journal.attempt")
    operation = journal["operation"]
    if operation not in {"activation", "rollback", "bootstrap_first_pair"}:
        raise DeploymentJournalError("journal.operation 不支持")
    revision = journal["revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise DeploymentJournalError("journal.revision 必须单调非负")
    if revision > 99_999_999_999_999_999_999:
        raise DeploymentJournalError("journal.revision 超出 Windows-safe filename 上限")
    phase = journal["phase"]
    if phase not in {*_operation_phases(str(operation)), _FAILURE_PHASE}:
        raise DeploymentJournalError("journal.phase 不支持")
    if (revision == 0) != (phase == "intent_durable"):
        raise DeploymentJournalError("revision 0 必须且只能是 intent_durable")
    _identifier(journal["nonce"], label="journal.nonce")

    timestamps = _closed(
        journal["timestamps"],
        {"created_at", "updated_at"},
        label="journal.timestamps",
    )
    created_at = _timestamp(timestamps["created_at"], label="journal.created_at")
    updated_at = _timestamp(timestamps["updated_at"], label="journal.updated_at")
    if updated_at < created_at:
        raise DeploymentJournalError("journal.updated_at 早于 created_at")
    previous_digest = _sha256(
        journal["previous_journal_sha256"],
        label="journal.previous_journal_sha256",
        nullable=True,
    )
    if (revision == 0) != (previous_digest is None):
        raise DeploymentJournalError("revision 0 与 previous hash 合同不符")

    if operation == "bootstrap_first_pair":
        if journal["original_pair"] is not None:
            raise DeploymentJournalError("bootstrap original pointer/binding 必须 absent")
        original = None
    else:
        original = _pair(
            journal["original_pair"],
            label="journal.original_pair",
            allow_missing_active=False,
            allow_missing_prior=True,
        )
    candidate = _release_ref(journal["candidate"], label="journal.candidate")
    target = _pair(
        journal["target_pair"],
        label="journal.target_pair",
        allow_missing_active=False,
        allow_missing_prior=operation == "bootstrap_first_pair",
    )
    original_active = None if original is None else original["active"]
    if operation == "activation":
        if (
            candidate != target["active"]
            or original_active != target["prior"]
            or candidate["manifest_sha256"] == original_active["manifest_sha256"]
        ):
            raise DeploymentJournalError("activation pair 方向不闭合")
        if original["prior"] is not None and (
            candidate["manifest_sha256"]
            == original["prior"]["manifest_sha256"]
        ):
            raise DeploymentJournalError("activation candidate 不得选择旧 prior")
    elif operation == "rollback":
        if (
            original["prior"] is None
            or candidate != original["prior"]
            or target["active"] != original["prior"]
            or target["prior"] != original_active
        ):
            raise DeploymentJournalError("rollback 只能交换 exact active/prior")
    elif candidate != target["active"] or target["prior"] is not None:
        raise DeploymentJournalError("bootstrap result 必须唯一为 active=R0/prior=null")

    pointer_cas = _closed(
        journal["pointer_cas"],
        {"expected", "desired"},
        label="journal.pointer_cas",
    )
    expected_pointer = (
        None
        if pointer_cas["expected"] is None
        else _release_ref(pointer_cas["expected"], label="pointer expected")
    )
    desired_pointer = _release_ref(pointer_cas["desired"], label="pointer desired")
    if expected_pointer != original_active or desired_pointer != target["active"]:
        raise DeploymentJournalError("pointer CAS 与 pair 不一致")
    binding_cas = _closed(
        journal["binding_cas"],
        {
            "expected_binding",
            "desired_binding",
            "expected_binding_sha256",
            "desired_binding_sha256",
        },
        label="journal.binding_cas",
    )
    expected_binding_sha256 = _sha256(
        binding_cas["expected_binding_sha256"],
        label="binding expected",
        nullable=True,
    )
    desired_binding = _sha256(
        binding_cas["desired_binding_sha256"],
        label="binding desired",
        nullable=operation == "bootstrap_first_pair",
    )
    if operation == "bootstrap_first_pair" and (
        binding_cas["expected_binding_sha256"] is not None
        or desired_binding is not None
        or binding_cas["expected_binding"] is not None
        or binding_cas["desired_binding"] is not None
    ):
        raise DeploymentJournalError("bootstrap 不得创建 local-prior binding")
    expected_binding_document = (
        None
        if binding_cas["expected_binding"] is None
        else _identity.validate_local_prior_binding(
            binding_cas["expected_binding"]
        )
    )
    desired_binding_document = (
        None
        if binding_cas["desired_binding"] is None
        else _identity.validate_local_prior_binding(
            binding_cas["desired_binding"]
        )
    )
    if (
        (expected_binding_document is None)
        != (expected_binding_sha256 is None)
        or (
            expected_binding_document is not None
            and expected_binding_document["binding_sha256"]
            != expected_binding_sha256
        )
        or (desired_binding_document is None) != (desired_binding is None)
        or (
            desired_binding_document is not None
            and desired_binding_document["binding_sha256"] != desired_binding
        )
    ):
        raise DeploymentJournalError(
            "binding CAS document/hash 必须逐字节内生闭合"
        )
    expected_pair = None if expected_binding_document is None else {
        "active": expected_binding_document["active"],
        "prior": expected_binding_document["prior"],
    }
    desired_pair = None if desired_binding_document is None else {
        "active": desired_binding_document["active"],
        "prior": desired_binding_document["prior"],
    }
    expected_original_binding_pair = (
        None
        if original is None or original["prior"] is None
        else original
    )
    if operation != "bootstrap_first_pair" and (
        expected_pair != expected_original_binding_pair
        or desired_pair != target
    ):
        raise DeploymentJournalError("binding CAS document 与 original/target pair 不一致")

    state_plan = _closed(
        journal["state_plan"],
        {
            "state_identity_sha256",
            "expand_plan_sha256",
            "compatibility_sha256",
            "database_names",
        },
        label="journal.state_plan",
    )
    for field in ("state_identity_sha256", "expand_plan_sha256", "compatibility_sha256"):
        _sha256(state_plan[field], label=f"state_plan.{field}")
    for binding_document in (
        expected_binding_document,
        desired_binding_document,
    ):
        if (
            binding_document is not None
            and binding_document["state_identity"]["identity_sha256"]
            != state_plan["state_identity_sha256"]
        ):
            raise DeploymentJournalError(
                "binding CAS document/authorization 与固定 D state identity 不一致"
            )
    database_names = state_plan["database_names"]
    if not isinstance(database_names, list) or not database_names:
        raise DeploymentJournalError("state_plan.database_names 必须非空")
    rendered_database_names = [
        _identifier(item, label="state plan database") for item in database_names
    ]
    if rendered_database_names != sorted(set(rendered_database_names)):
        raise DeploymentJournalError("state_plan.database_names 必须排序唯一")
    if rendered_database_names != ["comments", "research_workspace"]:
        raise DeploymentJournalError(
            "state_plan.database_names 必须是固定 production database 顺序"
        )

    seals = journal["database_seals"]
    if not isinstance(seals, list):
        raise DeploymentJournalError("database_seals 必须是 list")
    seal_names: list[str] = []
    for raw in seals:
        seal = _closed(
            raw,
            {"name", "seal_sha256", "compatibility_manifest_sha256"},
            label="journal.database_seal",
        )
        seal_names.append(_identifier(seal["name"], label="database seal name"))
        _sha256(seal["seal_sha256"], label="database seal hash")
        _sha256(
            seal["compatibility_manifest_sha256"],
            label="database compatibility hash",
        )
    if seal_names != sorted(seal_names) or len(seal_names) != len(set(seal_names)):
        raise DeploymentJournalError("database_seals 必须排序且唯一")
    if seals and _identity.identity_sha256(
        [
            {
                "name": seal["name"],
                "compatibility_manifest_sha256": seal[
                    "compatibility_manifest_sha256"
                ],
            }
            for seal in seals
        ]
    ) != state_plan["compatibility_sha256"]:
        raise DeploymentJournalError(
            "database_seals compatibility aggregate 未绑定 state_plan"
        )

    starts = journal["transient_start"]
    if not isinstance(starts, list):
        raise DeploymentJournalError("transient_start 必须是 list")
    start_keys: list[tuple[str, str]] = []
    start_roles: list[str] = []
    start_nonces: list[str] = []
    for raw in starts:
        start = _closed(
            raw,
            {"role", "release", "start_nonce", "scm_identity_sha256"},
            label="journal.transient_start item",
        )
        if start["role"] not in {"baseline", "candidate", "prior"}:
            raise DeploymentJournalError("transient start role 不支持")
        release = _release_ref(start["release"], label="transient start release")
        start_nonce = _identifier(
            start["start_nonce"], label="transient start nonce"
        )
        scm_identity_sha256 = _sha256(
            start["scm_identity_sha256"], label="transient SCM identity"
        )
        accepted_scm_identities = {
            _transient_scm_start_plan_sha256(journal, start)
        }
        # The private flag is used only while loading an entire persisted history;
        # validate_journal_history then requires that history to finish in the
        # failure terminal.  Public/single-revision validation and all new appends
        # remain bound exclusively to the current root-bundle executable.
        if _allow_legacy_scm_plan:
            accepted_scm_identities.add(
                _legacy_transient_scm_start_plan_sha256(journal, start)
            )
        if scm_identity_sha256 not in accepted_scm_identities:
            raise DeploymentJournalError(
                "transient_start authorization SCM start plan hash 不匹配"
            )
        start_keys.append((str(start["role"]), str(release["release_id"])))
        start_roles.append(str(start["role"]))
        start_nonces.append(start_nonce)
    if start_keys != sorted(start_keys) or len(start_keys) != len(set(start_keys)):
        raise DeploymentJournalError("transient_start 必须排序且唯一")
    if len(start_roles) != len(set(start_roles)):
        raise DeploymentJournalError("transient_start 每个 role 必须恰有一条记录")
    if len(start_nonces) != len(set(start_nonces)):
        raise DeploymentJournalError("transient_start 的 start_nonce 必须全局唯一")

    reserved = _closed(
        journal["reserved_receipt_ids"],
        {"activation", "rollback", "failure", "cleanup"},
        label="journal.reserved_receipt_ids",
    )
    rendered_reserved: dict[str, str | None] = {}
    for kind, raw in reserved.items():
        rendered_reserved[kind] = (
            None if raw is None else _identifier(raw, label=f"reserved {kind} receipt")
        )
    success_kind = "rollback" if operation == "rollback" else "activation"
    other_kind = "activation" if operation == "rollback" else "rollback"
    cleanup_required = operation != "bootstrap_first_pair"
    if (
        rendered_reserved[success_kind] is None
        or rendered_reserved[other_kind] is not None
        or rendered_reserved["failure"] is None
        or (rendered_reserved["cleanup"] is None) != (not cleanup_required)
    ):
        raise DeploymentJournalError("reserved receipt IDs 与 operation 不一致")
    nonnull_receipts = [item for item in rendered_reserved.values() if item is not None]
    if len({item.casefold() for item in nonnull_receipts}) != len(nonnull_receipts):
        raise DeploymentJournalError("reserved receipt IDs 必须唯一")

    cleanup_targets = journal["cleanup_targets"]
    if not isinstance(cleanup_targets, list):
        raise DeploymentJournalError("cleanup_targets 必须是 list")
    cleanup_keys: list[tuple[str, str, str]] = []
    cleanup_physical_keys: list[str] = []
    retained_hashes = {target["active"]["manifest_sha256"]}
    if target["prior"] is not None:
        retained_hashes.add(target["prior"]["manifest_sha256"])
    for raw in cleanup_targets:
        cleanup = _cleanup_target(raw, label="journal.cleanup_target")
        if (
            cleanup["kind"] == "release_closure"
            and cleanup["release"]["manifest_sha256"] in retained_hashes
        ):
            raise DeploymentJournalError("cleanup target 不得包含 target pair")
        cleanup_keys.append(_cleanup_sort_key(cleanup))
        cleanup_path = (
            cleanup["release"]["release_path"]
            if cleanup["kind"] == "release_closure"
            else cleanup["path"]
        )
        cleanup_physical_keys.append(
            unicodedata.normalize("NFKC", str(cleanup_path)).casefold()
        )
    if cleanup_keys != sorted(cleanup_keys) or len(cleanup_keys) != len(set(cleanup_keys)):
        raise DeploymentJournalError("cleanup_targets 必须排序且唯一")
    if len(cleanup_physical_keys) != len(set(cleanup_physical_keys)):
        raise DeploymentJournalError("cleanup_targets 含 case/NFKC physical duplicate")
    if operation == "bootstrap_first_pair" and cleanup_targets:
        raise DeploymentJournalError("bootstrap 不授权 ingress/cleanup")

    evidence = _closed(
        journal["evidence_hashes"],
        _EVIDENCE_FIELDS,
        label="journal.evidence_hashes",
    )
    for field, raw in evidence.items():
        _sha256(raw, label=f"evidence.{field}", nullable=True)
    authorization_fields: set[str] = set()
    for start in starts:
        field = _transient_start_authorization_evidence_field(start["role"])
        expected_hash = _transient_start_authorization_sha256(journal, start)
        if evidence[field] != expected_hash:
            raise DeploymentJournalError(
                "transient_start authorization evidence 未 exact 绑定 canonical material"
            )
        authorization_fields.add(field)
    for field in (
        "prior_start_authorization_sha256",
        "candidate_start_authorization_sha256",
    ):
        if evidence[field] is not None and field not in authorization_fields:
            raise DeploymentJournalError(
                "transient_start authorization evidence 没有对应 journal record"
            )
    if (
        evidence["state_compatibility_sha256"] is not None
        and evidence["state_compatibility_sha256"]
        != state_plan["compatibility_sha256"]
    ):
        raise DeploymentJournalError(
            "state compatibility evidence 未 exact 绑定 state_plan aggregate"
        )
    if phase == _FAILURE_PHASE:
        failure_fields = (
            "failure_original_pointer_observation_sha256",
            "failure_original_binding_observation_sha256",
            "failure_original_service_observation_sha256",
            "failure_original_writer_fence_observation_sha256",
            "failure_state_identity_observation_sha256",
        )
        if any(evidence[field] is None for field in failure_fields):
            raise DeploymentJournalError("failure terminal 缺原 authority/service/writer 恢复闭包")
    else:
        phases = _operation_phases(str(operation))
        rank = phases.index(str(phase))
        required_by_phase = {
            "root_preflight_verified": ("root_preflight_sha256",),
            "state_expand_applied": ("state_compatibility_sha256",),
            "prior_start_authorized": ("prior_start_authorization_sha256",),
            "prior_verified": ("prior_runtime_qualification_sha256",),
            "pointer_cas_committed": ("pointer_cas_observation_sha256",),
            "candidate_start_authorized": ("candidate_start_authorization_sha256",),
            "candidate_verified": ("candidate_runtime_qualification_sha256",),
            "binding_cas_committed": ("binding_cas_observation_sha256",),
            "terminal_receipt_committed": ("controller_verification_sha256",),
            "cleanup_authorized": ("cleanup_authorization_sha256",),
            "cleanup_receipt_committed": (
                "cleanup_receipt_sha256",
                "write_set_sha256",
            ),
        }
        if operation == "bootstrap_first_pair":
            required_by_phase.pop("terminal_receipt_committed")
        for required_phase, fields in required_by_phase.items():
            if required_phase in phases and rank >= phases.index(required_phase) and any(
                evidence[field] is None for field in fields
            ):
                raise DeploymentJournalError(
                    f"journal phase 缺 controller evidence hash: {required_phase}"
                )
        allowed_evidence: set[str] = set()
        for required_phase, fields in required_by_phase.items():
            if required_phase in phases and rank >= phases.index(required_phase):
                allowed_evidence.update(fields)
        if operation == "bootstrap_first_pair" and rank >= phases.index("terminal_receipt_committed"):
            if any(
                evidence[field] is None
                for field in (
                    "bootstrap_ingress_closed_sha256",
                    "bootstrap_legacy_c_writer_fence_sha256",
                    "candidate_runtime_qualification_sha256",
                )
            ):
                raise DeploymentJournalError("bootstrap receipt 缺 ingress/C-writer/R0 live fence seal")
            allowed_evidence.update(
                {
                    "bootstrap_ingress_closed_sha256",
                    "bootstrap_legacy_c_writer_fence_sha256",
                }
            )
        if any(
            evidence[field] is not None
            for field in _EVIDENCE_FIELDS - allowed_evidence
        ):
            raise DeploymentJournalError("journal 不得在对应 phase 前预填 evidence")

        starts_by_role = {str(item["role"]): item for item in starts}
        expected_starts: dict[str, Mapping[str, object]] = {}
        if "prior_start_authorized" in phases and rank >= phases.index("prior_start_authorized"):
            expected_prior = original_active if operation == "activation" else candidate
            expected_starts["prior"] = expected_prior
        if rank >= phases.index("candidate_start_authorized"):
            expected_starts[
                "baseline" if operation == "bootstrap_first_pair" else "candidate"
            ] = candidate
        if set(starts_by_role) != set(expected_starts) or any(
            starts_by_role[role]["release"] != reference
            for role, reference in expected_starts.items()
        ):
            raise DeploymentJournalError("transient_start 未精确绑定已授权 phase/release")

    state_was_applied = (
        evidence["state_compatibility_sha256"] is not None
        or (phase != _FAILURE_PHASE and _operation_phases(str(operation)).index(str(phase))
            >= _operation_phases(str(operation)).index("state_expand_applied"))
    )
    if state_was_applied and seal_names != rendered_database_names:
        raise DeploymentJournalError("database_seals 未精确闭合 state_plan database set")
    if not state_was_applied and seal_names:
        raise DeploymentJournalError("state apply 前不得预填 database seals")

    terminal = journal["terminal_receipt"]
    if terminal is None:
        if phase in {"terminal_receipt_committed", "cleanup_authorized", "cleanup_planned", "cleanup_receipt_committed", _FAILURE_PHASE}:
            raise DeploymentJournalError("终态 phase 缺 terminal receipt")
    else:
        raw_terminal = _object(terminal, label="journal.terminal_receipt")
        terminal_fields = {"kind", "receipt_id", "receipt_sha256"}
        if raw_terminal.get("kind") == "failure":
            terminal_fields.update({"operation", "failed_phase"})
        terminal_ref = _closed(
            terminal,
            terminal_fields,
            label="journal.terminal_receipt",
        )
        kind = terminal_ref["kind"]
        if kind not in {success_kind, "failure"}:
            raise DeploymentJournalError("成功/失败 terminal receipt 互斥")
        receipt_id = _identifier(terminal_ref["receipt_id"], label="terminal receipt ID")
        if receipt_id != rendered_reserved[kind]:
            raise DeploymentJournalError("terminal receipt 未使用预留 ID")
        _sha256(terminal_ref["receipt_sha256"], label="terminal receipt hash")
        if kind == "failure":
            if phase != _FAILURE_PHASE:
                raise DeploymentJournalError("failure terminal phase 不一致")
            expected_operation = _FAILURE_RECEIPT_OPERATION[str(operation)]
            if terminal_ref["operation"] != expected_operation:
                raise DeploymentJournalError(
                    "failure receipt operation differs from journal operation"
                )
            failed_phase = _identifier(
                terminal_ref["failed_phase"], label="terminal failed_phase"
            )
            if failed_phase != _expected_failed_phase(str(operation), int(revision)):
                raise DeploymentJournalError(
                    "failure failed_phase is not the last legal non-terminal phase"
                )
        elif phase not in {"terminal_receipt_committed", "cleanup_authorized", "cleanup_planned", "cleanup_receipt_committed"}:
            raise DeploymentJournalError("success terminal phase 不一致")
        if phase in {"cleanup_authorized", "cleanup_planned", "cleanup_receipt_committed"}:
            expected_authorization = _identity.identity_sha256(
                {
                    "attempt_id": journal["attempt"],
                    "terminal_receipt": terminal_ref,
                    "cleanup_targets": cleanup_targets,
                }
            )
            if evidence["cleanup_authorization_sha256"] != expected_authorization:
                raise DeploymentJournalError("cleanup_authorized 未绑定 exact receipt/targets")

    expected_hash = _sha256(journal["journal_sha256"], label="journal self hash")
    material = dict(journal)
    material.pop("journal_sha256")
    if _identity.identity_sha256(material) != expected_hash:
        raise DeploymentJournalError("journal self hash 不一致")
    return _json_clone(journal, label="deployment journal")


_IMMUTABLE_JOURNAL_FIELDS = {
    "schema_version",
    "attempt",
    "operation",
    "nonce",
    "original_pair",
    "candidate",
    "target_pair",
    "pointer_cas",
    "binding_cas",
    "state_plan",
    "reserved_receipt_ids",
    "cleanup_targets",
}


def validate_journal_history(
    values: Sequence[object],
    *,
    _allow_legacy_scm_plan: bool = False,
) -> tuple[Mapping[str, object], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not values:
        raise DeploymentJournalError("journal history 必须非空")
    history = tuple(
        validate_deployment_journal(
            value,
            _allow_legacy_scm_plan=_allow_legacy_scm_plan,
        )
        for value in values
    )
    first = history[0]
    terminal: object | None = None
    previous_updated: datetime | None = None
    if first["revision"] != 0 or first["phase"] != "intent_durable":
        raise DeploymentJournalError("revision 0 必须是 intent_durable")
    phases = _operation_phases(str(first["operation"]))
    for index, journal in enumerate(history):
        if journal["attempt"] != first["attempt"]:
            raise DeploymentJournalError("history 混入不同 attempt")
        if journal["revision"] != index:
            raise DeploymentJournalError("journal revision 必须从 0 连续递增")
        expected_previous = None if index == 0 else history[index - 1]["journal_sha256"]
        if journal["previous_journal_sha256"] != expected_previous:
            raise DeploymentJournalError("previous_journal_sha256 链不连续")
        for field in _IMMUTABLE_JOURNAL_FIELDS:
            if journal[field] != first[field]:
                raise DeploymentJournalError(f"journal immutable field 漂移: {field}")
        if journal["timestamps"]["created_at"] != first["timestamps"]["created_at"]:
            raise DeploymentJournalError("journal created_at 不得改写")
        if index > 0:
            previous = history[index - 1]
            for field, prior_hash in previous["evidence_hashes"].items():
                current_hash = journal["evidence_hashes"][field]
                if prior_hash is not None and current_hash != prior_hash:
                    raise DeploymentJournalError("controller evidence hash 不得改写或消失")
            previous_seals = {
                str(item["name"]): item for item in previous["database_seals"]
            }
            current_seals = {
                str(item["name"]): item for item in journal["database_seals"]
            }
            if any(current_seals.get(name) != seal for name, seal in previous_seals.items()):
                raise DeploymentJournalError("database seal 不得改写或消失")
            previous_starts = {
                (str(item["role"]), str(item["release"]["manifest_sha256"])): item
                for item in previous["transient_start"]
            }
            current_starts = {
                (str(item["role"]), str(item["release"]["manifest_sha256"])): item
                for item in journal["transient_start"]
            }
            if any(current_starts.get(key) != item for key, item in previous_starts.items()):
                raise DeploymentJournalError("transient start identity 不得改写或消失")
            if journal["phase"] == _FAILURE_PHASE:
                if current_seals != previous_seals or current_starts != previous_starts:
                    raise DeploymentJournalError(
                        "failure revision 不得新增 database seal/transient start"
                    )
                failure_only = {
                    "failure_original_pointer_observation_sha256",
                    "failure_original_binding_observation_sha256",
                    "failure_original_service_observation_sha256",
                    "failure_original_writer_fence_observation_sha256",
                    "failure_state_identity_observation_sha256",
                }
                if any(
                    journal["evidence_hashes"][field]
                    != previous["evidence_hashes"][field]
                    for field in _EVIDENCE_FIELDS - failure_only
                ):
                    raise DeploymentJournalError(
                        "failure revision 只能追加 sealed restoration observations"
                    )
        updated = _timestamp(
            journal["timestamps"]["updated_at"], label="journal.updated_at"
        )
        if previous_updated is not None and updated < previous_updated:
            raise DeploymentJournalError("journal updated_at 倒退")
        previous_updated = updated
        phase = str(journal["phase"])
        if phase == _FAILURE_PHASE:
            if index != len(history) - 1:
                raise DeploymentJournalError("failure terminal 后不得追加 revision")
            if (
                index == 0
                or journal["terminal_receipt"]["failed_phase"]
                != history[index - 1]["phase"]
            ):
                raise DeploymentJournalError(
                    "failure failed_phase must equal the preceding journal phase"
                )
        else:
            expected_phase = phases[index] if index < len(phases) else None
            if phase != expected_phase:
                raise DeploymentJournalError("journal phase 必须逐阶段前进，禁止跳跃/重复")
        current_terminal = journal["terminal_receipt"]
        if terminal is None and current_terminal is not None:
            terminal = current_terminal
        elif terminal is not None and current_terminal != terminal:
            raise DeploymentJournalError("同 attempt 出现多个互斥终态")
        elif terminal is not None and current_terminal is None:
            raise DeploymentJournalError("terminal receipt 不得在后续 revision 消失")
        if _journal_is_closed(journal) and index != len(history) - 1:
            raise DeploymentJournalError("attempt 终态后不得追加 revision")
    if _allow_legacy_scm_plan:
        scm_generations: set[str] = set()
        for journal in history:
            for start in journal["transient_start"]:
                observed = str(start["scm_identity_sha256"])
                if observed == _transient_scm_start_plan_sha256(journal, start):
                    scm_generations.add("current")
                elif observed == _legacy_transient_scm_start_plan_sha256(
                    journal, start
                ):
                    scm_generations.add("legacy")
        if "legacy" in scm_generations and (
            history[-1]["phase"] != _FAILURE_PHASE
            or scm_generations != {"legacy"}
        ):
            raise DeploymentJournalError(
                "legacy SCM start plan 只允许完整、单代且 failure-closed 的历史"
            )
    return history


class DeploymentJournalStore:
    def __init__(
        self,
        *,
        layout: LocalDeploymentLayout,
        safe_root: _SafeRoot,
        authority_token: object,
    ):
        self._layout = layout
        self._safe_root = safe_root
        self._authority_token = authority_token

    @staticmethod
    def _filename(attempt: str, revision: int) -> str:
        return f"{attempt}.r{revision:020d}.json"

    def _validate_evidence_directory(self, path: Path, *, attempt: str) -> None:
        self._safe_root.preflight(
            path, expected_kind="directory", allow_absent=False
        )
        try:
            entries = sorted(os.scandir(path), key=lambda item: item.name)
        except OSError as error:
            raise DeploymentJournalError("无法枚举 attempt evidence") from error
        names: dict[str, str] = {}
        for entry in entries:
            match = _EVIDENCE_FILE_RE.fullmatch(entry.name)
            if match is None:
                raise DeploymentJournalError("attempt evidence 目录含非合同文件")
            evidence_id = _identifier(
                match.group(1), label="attempt evidence filename"
            )
            folded = evidence_id.casefold()
            previous = names.get(folded)
            if previous is not None and previous != evidence_id:
                raise DeploymentJournalError("attempt evidence 存在 case-fold 碰撞")
            names[folded] = evidence_id
            record = _canonical_read(
                path / entry.name,
                safe_root=self._safe_root,
                validator=_validate_attempt_evidence,
                label=f"attempt {attempt} evidence",
            )
            if record is None:
                raise DeploymentJournalError("attempt evidence 枚举后消失")

    def _read_all(self) -> Mapping[str, tuple[Mapping[str, object], ...]]:
        self._safe_root.preflight(
            self._layout.journals,
            expected_kind="directory",
            allow_absent=False,
        )
        grouped: dict[str, list[tuple[int, Mapping[str, object]]]] = {}
        names: dict[str, str] = {}
        try:
            entries = sorted(os.scandir(self._layout.journals), key=lambda item: item.name)
        except OSError as error:
            raise DeploymentJournalError("无法枚举 deployment journals") from error
        for entry in entries:
            match = _JOURNAL_NAME_RE.fullmatch(entry.name)
            if match is None:
                evidence_match = _EVIDENCE_DIRECTORY_RE.fullmatch(entry.name)
                if evidence_match is None:
                    raise DeploymentJournalError("journal 目录含非合同文件")
                attempt = _identifier(
                    evidence_match.group(1), label="evidence directory attempt"
                )
                folded = attempt.casefold()
                previous_name = names.get(folded)
                if previous_name is not None and previous_name != attempt:
                    raise DeploymentJournalError("journal/evidence attempt 大小写漂移")
                names[folded] = attempt
                self._validate_evidence_directory(
                    self._layout.journals / entry.name,
                    attempt=attempt,
                )
                continue
            attempt, revision_text = match.groups()
            _identifier(attempt, label="journal filename attempt")
            folded = attempt.casefold()
            previous_name = names.get(folded)
            if previous_name is not None and previous_name != attempt:
                raise DeploymentJournalError("journal attempt 存在 case-fold 碰撞")
            names[folded] = attempt
            path = self._layout.journals / entry.name
            record = _canonical_read(
                path,
                safe_root=self._safe_root,
                validator=lambda value: validate_deployment_journal(
                    value,
                    _allow_legacy_scm_plan=True,
                ),
                label="deployment journal revision",
            )
            if record is None:
                raise DeploymentJournalError("journal 枚举后消失")
            revision = int(revision_text)
            if record.value["attempt"] != attempt or record.value["revision"] != revision:
                raise DeploymentJournalError("journal filename 与 payload 不一致")
            grouped.setdefault(folded, []).append((revision, record.value))
        histories: dict[str, tuple[Mapping[str, object], ...]] = {}
        reserved_global: set[str] = set()
        nonce_global: set[str] = set()
        for folded, items in grouped.items():
            items.sort(key=lambda item: item[0])
            history = validate_journal_history(
                [item[1] for item in items],
                _allow_legacy_scm_plan=True,
            )
            nonce = str(history[0]["nonce"]).casefold()
            if nonce in nonce_global:
                raise DeploymentJournalError("不同 attempt 不得复用 nonce")
            nonce_global.add(nonce)
            for raw in history[0]["reserved_receipt_ids"].values():
                if raw is None:
                    continue
                rendered = str(raw).casefold()
                if rendered in reserved_global:
                    raise DeploymentJournalError("不同 attempt 不得复用 receipt ID")
                reserved_global.add(rendered)
            histories[folded] = history
        return histories

    def histories(self) -> Mapping[str, tuple[Mapping[str, object], ...]]:
        return dict(self._read_all())

    def replay(self, attempt: str) -> tuple[Mapping[str, object], ...]:
        attempt = _identifier(attempt, label="attempt")
        history = self._read_all().get(attempt.casefold())
        if history is None:
            raise DeploymentJournalError("attempt journal 不存在")
        return history

    def active_revisions(self) -> tuple[Mapping[str, object], ...]:
        active: list[Mapping[str, object]] = []
        for history in self._read_all().values():
            latest = history[-1]
            if not _journal_is_closed(latest):
                active.append(latest)
        return tuple(sorted(active, key=lambda item: str(item["attempt"])))

    def append(
        self,
        value: object,
        *,
        lock: CrashReleasedFileLock,
    ) -> Mapping[str, object]:
        lock.assert_held(authority_token=self._authority_token)
        journal = validate_deployment_journal(value)
        histories = self._read_all()
        folded = str(journal["attempt"]).casefold()
        existing = histories.get(folded)
        revision = int(journal["revision"])
        if existing is not None and revision < len(existing):
            if existing[revision] == journal:
                return existing[revision]
            raise DeploymentJournalError("attempt revision 已存在第三值")
        if existing is None:
            candidate_history = (journal,)
        else:
            candidate_history = (*existing, journal)
        validate_journal_history(candidate_history)

        if existing is None:
            nonce = str(journal["nonce"]).casefold()
            receipt_ids = {
                str(item).casefold()
                for item in journal["reserved_receipt_ids"].values()
                if item is not None
            }
            for history in histories.values():
                if str(history[0]["nonce"]).casefold() == nonce:
                    raise DeploymentJournalError("attempt nonce 已被占用")
                occupied = {
                    str(item).casefold()
                    for item in history[0]["reserved_receipt_ids"].values()
                    if item is not None
                }
                if receipt_ids & occupied:
                    raise DeploymentJournalError("reserved receipt ID 已被其他 attempt 占用")

        final = self._layout.journals / self._filename(
            str(journal["attempt"]), int(journal["revision"])
        )
        if self._safe_root.preflight(
            final, expected_kind="file", allow_absent=True
        ) is not None:
            record = _canonical_read(
                final,
                safe_root=self._safe_root,
                validator=validate_deployment_journal,
                label="deployment journal revision",
            )
            if record is not None and record.value == journal:
                return record.value
            raise DeploymentJournalError("attempt revision 已存在第三值")
        raw = _identity.canonical_bytes(journal)
        with _BoundDirectory(
            self._safe_root, self._layout.journals
        ) as journal_guard:
            observed_under_guard = _canonical_read(
                final,
                safe_root=self._safe_root,
                validator=validate_deployment_journal,
                label="deployment journal revision",
            )
            if observed_under_guard is not None:
                if observed_under_guard.value == journal:
                    return observed_under_guard.value
                raise DeploymentJournalError("attempt revision create-only 前出现第三值")
            _write_new_bound_file(
                journal_guard,
                name=final.name,
                raw=raw,
                label="deployment journal revision",
            )
        replayed = self.replay(str(journal["attempt"]))
        if replayed[-1] != journal:
            raise DeploymentJournalError("journal 持久写后重放不一致")
        return replayed[-1]


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse(before)
            or getattr(before, "st_nlink", 1) != 1
        ):
            raise RetentionPlanningError("closure file 不是普通独占文件")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    observed = os.lstat(path)
    if (
        not _same_file_identity(before, after)
        or not _same_file_identity(after, observed)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise RetentionPlanningError("closure file 在 hash 期间发生身份漂移")
    return digest.hexdigest()


class LocalDeploymentPersistence:
    """B2 隔离持久化 façade；没有部署、probe 或 delete 方法。"""

    __slots__ = (
        "_test_only",
        "_allow_posix_test_only",
        "_safe_root",
        "layout",
        "_authority_token",
        "_active",
        "_binding",
        "journals",
        "__weakref__",
    )

    def __init__(
        self,
        root: Path,
        *,
        _construction_token: object,
        _test_token: object | None,
        _allow_posix_test_only: bool,
        _create_layout: bool,
    ):
        if _construction_token is not _CONSTRUCTION_TOKEN:
            raise UnsafeLocalPath("必须使用 production 或 for_test_only 工厂")
        if _test_token not in {None, _TEST_ONLY_TOKEN}:
            raise UnsafeLocalPath("test-only adapter 身份无效")
        self._test_only = _test_token is _TEST_ONLY_TOKEN
        if not self._test_only:
            if os.name != "nt":
                raise UnsafeLocalPath("生产 runtime 只允许 Windows exact D root")
            if str(root) != PRODUCTION_VM_ROOT_TEXT:
                raise UnsafeLocalPath("生产 root 常量发生漂移")
            if str(_identity.PRODUCTION_VM_ROOT) != PRODUCTION_VM_ROOT_TEXT:
                raise UnsafeLocalPath("B1/B2 产品 D-root 常量不一致")
        self._allow_posix_test_only = _allow_posix_test_only
        self._safe_root = _SafeRoot(
            root,
            allow_posix_test_only=_allow_posix_test_only,
        )
        if _create_layout:
            self._safe_root.create_layout()
        self.layout = LocalDeploymentLayout(root=root)
        self._authority_token = object()
        self._active = _CanonicalCasAuthority(
            path=self.layout.active_release,
            label="active_release.json",
            validator=_identity.validate_active_release,
            safe_root=self._safe_root,
            temporary_directory=self.layout.temporary,
            authority_token=self._authority_token,
        )
        self._binding = _CanonicalCasAuthority(
            path=self.layout.local_prior_binding,
            label="local_prior_binding.json",
            validator=_identity.validate_local_prior_binding,
            safe_root=self._safe_root,
            temporary_directory=self.layout.temporary,
            authority_token=self._authority_token,
        )
        self.journals = DeploymentJournalStore(
            layout=self.layout,
            safe_root=self._safe_root,
            authority_token=self._authority_token,
        )
        if not self._test_only:
            _LIVE_PRODUCTION_PERSISTENCE[id(self)] = (
                self,
                self._safe_root,
                self.layout,
                self._authority_token,
                self._active,
                self._binding,
                self.journals,
            )

    def _assert_production_provenance(self) -> None:
        expected = _LIVE_PRODUCTION_PERSISTENCE.get(id(self))
        observed = (
            self,
            getattr(self, "_safe_root", None),
            getattr(self, "layout", None),
            getattr(self, "_authority_token", None),
            getattr(self, "_active", None),
            getattr(self, "_binding", None),
            getattr(self, "journals", None),
        )
        if (
            type(self) is not LocalDeploymentPersistence
            or expected is None
            or len(expected) != len(observed)
            or any(left is not right for left, right in zip(expected, observed))
            or self._test_only
            or self._allow_posix_test_only
            or str(self.layout.root) != PRODUCTION_VM_ROOT_TEXT
            or str(self._safe_root.root) != PRODUCTION_VM_ROOT_TEXT
        ):
            raise UnsafeLocalPath("production persistence provenance differs")

    @classmethod
    def production(cls) -> "LocalDeploymentPersistence":
        """构造唯一产品根；没有调用者可提供的 root 参数。"""

        return cls(
            Path(PRODUCTION_VM_ROOT_TEXT),
            _construction_token=_CONSTRUCTION_TOKEN,
            _test_token=None,
            _allow_posix_test_only=False,
            _create_layout=True,
        )

    @classmethod
    def production_read_only(cls) -> "LocalDeploymentPersistence":
        """Bind the existing exact D layout without creating any member."""

        return cls(
            Path(PRODUCTION_VM_ROOT_TEXT),
            _construction_token=_CONSTRUCTION_TOKEN,
            _test_token=None,
            _allow_posix_test_only=False,
            _create_layout=False,
        )

    @classmethod
    def for_test_only(
        cls,
        root: Path,
        *,
        allow_posix_test_only: bool = False,
    ) -> "LocalDeploymentPersistence":
        """显式隔离测试工厂；不得由 CLI、env 或 config 路由。"""

        if not isinstance(root, Path):
            raise UnsafeLocalPath("test-only root 必须显式传 Path")
        if _aliases_exact_production_root(root):
            raise UnsafeLocalPath(
                "test-only persistence 不得绑定 production exact D root/alias"
            )
        return cls(
            root,
            _construction_token=_CONSTRUCTION_TOKEN,
            _test_token=_TEST_ONLY_TOKEN,
            _allow_posix_test_only=(os.name == "nt" or allow_posix_test_only),
            _create_layout=True,
        )

    def assert_write_path(self, path: Path) -> None:
        """只做写前机械验证，不创建目标。"""

        self._safe_root.preflight(path, allow_absent=True)

    def assert_global_lock(self, lock: CrashReleasedFileLock) -> None:
        """证明 lock 属于同一 persistence 且由当前进程/线程持有。"""

        lock.assert_held(authority_token=self._authority_token)

    def lock_bootstrap_comment_schema_expand_authorization(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> LockedBootstrapCommentSchemaExpandAuthorization:
        """从同 epoch durable root-preflight 派生唯一 comments expand 能力。"""

        if (
            type(lock) is not CrashReleasedFileLock
            or type(workspace) is not LockedAttemptWorkspace
        ):
            raise DeploymentLockBusy(
                "bootstrap comment schema expand 必须绑定 exact lock/workspace"
            )
        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            workspace._lock is not lock
            or workspace._authority_token is not self._authority_token
            or workspace._safe_root is not self._safe_root
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "bootstrap comment schema expand 必须绑定同一 persistence/lock/workspace epoch"
            )
        history = self.journals.replay(workspace.attempt_id)
        latest = history[-1]
        if (
            latest["attempt"] != workspace.attempt_id
            or latest["nonce"] != workspace.nonce
            or latest["operation"] != "bootstrap_first_pair"
            or latest["phase"] != "root_preflight_verified"
        ):
            raise DeploymentJournalError(
                "bootstrap comment schema expand 只接受 exact durable root preflight"
            )
        authorization = LockedBootstrapCommentSchemaExpandAuthorization(
            persistence=self,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            journal_sha256=str(latest["journal_sha256"]),
            state_identity_sha256=str(
                latest["state_plan"]["state_identity_sha256"]
            ),
            candidate_reference=latest["candidate"],
            _construction_token=(
                _LOCKED_BOOTSTRAP_COMMENT_SCHEMA_EXPAND_AUTHORIZATION_TOKEN
            ),
        )
        authorization._assert_live()
        return authorization

    def global_lock(self) -> CrashReleasedFileLock:
        return CrashReleasedFileLock(
            path=self.layout.deployment_lock,
            safe_root=self._safe_root,
            allow_posix_test_only=self._allow_posix_test_only,
            authority_token=self._authority_token,
        )

    def _active_failure_steady_recovery_authorization(
        self,
    ) -> Mapping[str, object] | None:
        """Resolve the sole durable authorization for a pending failure restart."""

        active = self.journals.active_revisions()
        if not active:
            return None
        if len(active) != 1:
            raise DeploymentJournalError(
                "failure recovery 要求恰一 active deployment journal"
            )
        journal = active[0]
        if journal["operation"] not in {"activation", "rollback"}:
            raise DeploymentJournalError(
                "bootstrap active journal 不得授权 ordinary failure recovery"
            )
        attempt = str(journal["attempt"])
        path = (
            self.layout.journals
            / f"{attempt}.evidence"
            / "failure-steady-recovery-authorization.json"
        )
        record = _canonical_read(
            path,
            safe_root=self._safe_root,
            validator=_validate_failure_steady_recovery_authorization,
            label="failure steady recovery authorization",
        )
        if record is None:
            return None
        authorization = record.value
        expected_pair = journal["original_pair"]
        expected_binding = journal["binding_cas"]["expected_binding"]
        expected_active_raw = _identity.canonical_bytes(
            {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": expected_pair["active"],
            }
        )
        expected_binding_raw_sha256 = (
            hashlib.sha256(b"absent").hexdigest()
            if expected_binding is None
            else hashlib.sha256(
                _identity.canonical_bytes(
                    _identity.validate_local_prior_binding(expected_binding)
                )
            ).hexdigest()
        )
        if (
            authorization["attempt_id"] != attempt
            or authorization["nonce"] != journal["nonce"]
            or authorization["operation"] != journal["operation"]
            or authorization["failed_phase"] != journal["phase"]
            or authorization["journal_sha256"] != journal["journal_sha256"]
            or authorization["original_pair"] != expected_pair
            or authorization["candidate"] != journal["candidate"]
            or authorization["state_identity_sha256"]
            != journal["state_plan"]["state_identity_sha256"]
            or authorization["active_pointer_raw_sha256"]
            != hashlib.sha256(expected_active_raw).hexdigest()
            or authorization["local_prior_binding_raw_sha256"]
            != expected_binding_raw_sha256
        ):
            raise DeploymentJournalError(
                "failure steady recovery authorization 未 exact 绑定 active journal"
            )
        active_record = self.read_active_release()
        binding_record = self.read_local_prior_binding()
        if (
            active_record is None
            or active_record.raw != expected_active_raw
            or (None if binding_record is None else binding_record.value)
            != expected_binding
        ):
            raise DeploymentJournalError(
                "failure steady recovery authorization 与 live original control 不一致"
            )
        return authorization

    def read_failure_steady_recovery_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt_id: str,
        nonce: str,
    ) -> Mapping[str, object] | None:
        """在部署全局锁内解析当前 attempt 的单向失败恢复授权。

        该入口专供 controller 的 fresh-process replay 使用。只要 durable
        authorization 已存在，调用方就不得再进入 candidate qualification、
        pointer/binding CAS 或其他 forward phase；损坏、漂移或属于其他
        attempt 的 marker 一律 fail closed。
        """

        self.assert_global_lock(lock)
        expected_attempt = _identifier(
            attempt_id, label="failure recovery attempt"
        )
        expected_nonce = _identifier(nonce, label="failure recovery nonce")
        authorization = self._active_failure_steady_recovery_authorization()
        if authorization is None:
            return None
        if (
            authorization["attempt_id"] != expected_attempt
            or authorization["nonce"] != expected_nonce
        ):
            raise DeploymentJournalError(
                "active failure recovery authorization 不属于请求 attempt"
            )
        return authorization

    @staticmethod
    def _failure_selection_control_sets(
        journal: Mapping[str, object],
    ) -> tuple[list[str], list[str]]:
        absent_sha256 = hashlib.sha256(b"absent").hexdigest()
        original_active = _identity.validate_active_release(
            {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": journal["original_pair"]["active"],  # type: ignore[index]
            }
        )
        target_active = _identity.validate_active_release(
            {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": journal["pointer_cas"]["desired"],  # type: ignore[index]
            }
        )
        active_hashes = sorted(
            {
                hashlib.sha256(_identity.canonical_bytes(original_active)).hexdigest(),
                hashlib.sha256(_identity.canonical_bytes(target_active)).hexdigest(),
            }
        )
        binding_hashes: set[str] = set()
        for value in (
            journal["binding_cas"]["expected_binding"],  # type: ignore[index]
            journal["binding_cas"]["desired_binding"],  # type: ignore[index]
        ):
            if value is None:
                binding_hashes.add(absent_sha256)
            else:
                binding_hashes.add(
                    hashlib.sha256(
                        _identity.canonical_bytes(
                            _identity.validate_local_prior_binding(value)
                        )
                    ).hexdigest()
                )
        return active_hashes, sorted(binding_hashes)

    def _active_failure_selection_authorization(
        self,
    ) -> Mapping[str, object] | None:
        active_journals = self.journals.active_revisions()
        if not active_journals:
            return None
        if len(active_journals) != 1:
            raise DeploymentJournalError(
                "failure selection requires exactly one active journal"
            )
        journal = active_journals[0]
        if journal["operation"] not in {"activation", "rollback"}:
            return None
        attempt = str(journal["attempt"])
        record = _canonical_read(
            self.layout.journals
            / f"{attempt}.evidence"
            / "failure-selection-authorization.json",
            safe_root=self._safe_root,
            validator=_validate_failure_selection_authorization,
            label="failure selection authorization",
        )
        if record is None:
            return None
        authorization = record.value
        active_hashes, binding_hashes = self._failure_selection_control_sets(
            journal
        )
        if (
            authorization["attempt_id"] != attempt
            or authorization["nonce"] != journal["nonce"]
            or authorization["operation"] != journal["operation"]
            or authorization["failed_phase"] != journal["phase"]
            or authorization["journal_sha256"] != journal["journal_sha256"]
            or authorization["original_pair"] != journal["original_pair"]
            or authorization["target_pair"] != journal["target_pair"]
            or authorization["candidate"] != journal["candidate"]
            or authorization["state_identity_sha256"]
            != journal["state_plan"]["state_identity_sha256"]
            or authorization["allowed_active_control_sha256"] != active_hashes
            or authorization["allowed_binding_control_sha256"] != binding_hashes
        ):
            raise DeploymentJournalError(
                "failure selection authorization is not exact current journal"
            )
        active_record = self.read_active_release()
        binding_record = self.read_local_prior_binding()
        absent_sha256 = hashlib.sha256(b"absent").hexdigest()
        active_sha256 = (
            absent_sha256 if active_record is None else active_record.sha256
        )
        binding_sha256 = (
            absent_sha256 if binding_record is None else binding_record.sha256
        )
        if active_sha256 not in active_hashes or binding_sha256 not in binding_hashes:
            raise DeploymentJournalError(
                "failure selection observed control outside original/target states"
            )
        return authorization

    def read_failure_selection_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt_id: str,
        nonce: str,
    ) -> Mapping[str, object] | None:
        self.assert_global_lock(lock)
        expected_attempt = _identifier(
            attempt_id, label="failure selection attempt"
        )
        expected_nonce = _identifier(nonce, label="failure selection nonce")
        authorization = self._active_failure_selection_authorization()
        if authorization is None:
            return None
        if (
            authorization["attempt_id"] != expected_attempt
            or authorization["nonce"] != expected_nonce
        ):
            raise DeploymentJournalError(
                "failure selection authorization belongs to another attempt"
            )
        return authorization

    def commit_failure_selection_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> Mapping[str, object]:
        """Durably select ordinary failure before stop/reverse-CAS effects."""

        self.assert_global_lock(lock)
        workspace._assert_live()
        journal = self.journals.replay(workspace.attempt_id)[-1]
        if (
            journal["nonce"] != workspace.nonce
            or journal["operation"] not in {"activation", "rollback"}
            or _journal_is_closed(journal)
        ):
            raise DeploymentJournalError(
                "failure selection requires an exact ordinary active journal"
            )
        active_hashes, binding_hashes = self._failure_selection_control_sets(
            journal
        )
        absent_sha256 = hashlib.sha256(b"absent").hexdigest()
        active_record = self.read_active_release()
        binding_record = self.read_local_prior_binding()
        if (
            (absent_sha256 if active_record is None else active_record.sha256)
            not in active_hashes
            or (absent_sha256 if binding_record is None else binding_record.sha256)
            not in binding_hashes
        ):
            raise DeploymentJournalError(
                "failure selection current control is outside original/target states"
            )
        body: dict[str, object] = {
            "schema_version": _FAILURE_SELECTION_AUTHORIZATION_SCHEMA,
            "scope": _FAILURE_SELECTION_AUTHORIZATION_SCOPE,
            "attempt_id": journal["attempt"],
            "nonce": journal["nonce"],
            "operation": journal["operation"],
            "failed_phase": journal["phase"],
            "journal_sha256": journal["journal_sha256"],
            "original_pair": journal["original_pair"],
            "target_pair": journal["target_pair"],
            "candidate": journal["candidate"],
            "state_identity_sha256": journal["state_plan"][
                "state_identity_sha256"
            ],
            "allowed_active_control_sha256": active_hashes,
            "allowed_binding_control_sha256": binding_hashes,
        }
        body["authorization_sha256"] = _identity.identity_sha256(body)
        validated = _validate_failure_selection_authorization(body)
        record = self.commit_attempt_evidence(
            lock,
            workspace.attempt_id,
            "failure-selection-authorization",
            _identity.canonical_bytes(validated),
        )
        if record.value != validated:
            raise CompareAndSwapConflict(
                "failure selection authorization create-through drifted"
            )
        if self._active_failure_selection_authorization() != validated:
            raise CompareAndSwapConflict(
                "failure selection authorization durable replay drifted"
            )
        return validated

    def _active_bootstrap_failure_authorization(
        self,
    ) -> Mapping[str, object] | None:
        active = self.journals.active_revisions()
        if not active:
            return None
        if len(active) != 1:
            raise DeploymentJournalError(
                "bootstrap failure recovery requires exactly one active journal"
            )
        journal = active[0]
        if journal["operation"] != "bootstrap_first_pair":
            return None
        attempt = str(journal["attempt"])
        record = _canonical_read(
            self.layout.journals
            / f"{attempt}.evidence"
            / "bootstrap-failure-authorization.json",
            safe_root=self._safe_root,
            validator=_validate_bootstrap_failure_authorization,
            label="bootstrap failure authorization",
        )
        if record is None:
            return None
        authorization = record.value
        absent_sha256 = hashlib.sha256(b"absent").hexdigest()
        if (
            authorization["attempt_id"] != attempt
            or authorization["nonce"] != journal["nonce"]
            or authorization["failed_phase"] != journal["phase"]
            or authorization["journal_sha256"] != journal["journal_sha256"]
            or authorization["candidate"] != journal["candidate"]
            or authorization["state_identity_sha256"]
            != journal["state_plan"]["state_identity_sha256"]
            or authorization["active_pointer_raw_sha256"] != absent_sha256
            or authorization["local_prior_binding_raw_sha256"] != absent_sha256
        ):
            raise DeploymentJournalError(
                "bootstrap failure authorization is not exact current journal state"
            )
        current_active = self.read_active_release()
        if (
            self.read_local_prior_binding() is not None
            or (
                current_active is not None
                and current_active.value.get("release") != journal["candidate"]
            )
        ):
            raise DeploymentJournalError(
                "bootstrap failure authorization observed a third control state"
            )
        return authorization

    def read_bootstrap_failure_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt_id: str,
        nonce: str,
    ) -> Mapping[str, object] | None:
        """Read the one-way bootstrap failure marker under the global lock."""

        self.assert_global_lock(lock)
        expected_attempt = _identifier(
            attempt_id, label="bootstrap failure attempt"
        )
        expected_nonce = _identifier(nonce, label="bootstrap failure nonce")
        authorization = self._active_bootstrap_failure_authorization()
        if authorization is None:
            return None
        if (
            authorization["attempt_id"] != expected_attempt
            or authorization["nonce"] != expected_nonce
        ):
            raise DeploymentJournalError(
                "bootstrap failure authorization belongs to another attempt"
            )
        return authorization

    def commit_bootstrap_failure_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> Mapping[str, object]:
        """Select bootstrap failure before the first reverse-control write."""

        self.assert_global_lock(lock)
        workspace._assert_live()
        journal = self.journals.replay(workspace.attempt_id)[-1]
        absent_sha256 = hashlib.sha256(b"absent").hexdigest()
        current_active = self.read_active_release()
        if (
            journal["nonce"] != workspace.nonce
            or journal["operation"] != "bootstrap_first_pair"
            or _journal_is_closed(journal)
            or self.read_local_prior_binding() is not None
            or (
                current_active is not None
                and current_active.value.get("release") != journal["candidate"]
            )
        ):
            raise DeploymentJournalError(
                "bootstrap failure marker requires current candidate-or-absent controls"
            )
        state_sources: dict[str, LockedStateSqliteSource] = {}
        try:
            for database in _STATE_SQLITE_DATABASES:
                state_sources[database] = self.lock_state_sqlite_source(
                    lock, workspace, database
                )
            state_order_sha256 = _locked_production_state_order_sha256(
                state_sources,
                persistence=self,
                workspace=workspace,
            )
        finally:
            for source in reversed(tuple(state_sources.values())):
                source.close()
        body: dict[str, object] = {
            "schema_version": _BOOTSTRAP_FAILURE_AUTHORIZATION_SCHEMA,
            "scope": _BOOTSTRAP_FAILURE_AUTHORIZATION_SCOPE,
            "attempt_id": journal["attempt"],
            "nonce": journal["nonce"],
            "operation": "bootstrap_first_pair",
            "failed_phase": journal["phase"],
            "journal_sha256": journal["journal_sha256"],
            "candidate": journal["candidate"],
            "state_identity_sha256": journal["state_plan"][
                "state_identity_sha256"
            ],
            "active_pointer_raw_sha256": absent_sha256,
            "local_prior_binding_raw_sha256": absent_sha256,
            "production_state_order_sha256": state_order_sha256,
        }
        body["authorization_sha256"] = _identity.identity_sha256(body)
        validated = _validate_bootstrap_failure_authorization(body)
        record = self.commit_attempt_evidence(
            lock,
            workspace.attempt_id,
            "bootstrap-failure-authorization",
            _identity.canonical_bytes(validated),
        )
        if record.value != validated:
            raise CompareAndSwapConflict(
                "bootstrap failure authorization create-through drifted"
            )
        if self._active_bootstrap_failure_authorization() != validated:
            raise CompareAndSwapConflict(
                "bootstrap failure authorization durable replay drifted"
            )
        return validated

    def commit_failure_steady_recovery_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        restoration: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Durably authorize only the restored original release to restart."""

        self.assert_global_lock(lock)
        workspace._assert_live()
        journal = self.journals.replay(workspace.attempt_id)[-1]
        if (
            journal["nonce"] != workspace.nonce
            or journal["operation"] not in {"activation", "rollback"}
            or _journal_is_closed(journal)
            or restoration.get("journal_sha256") != journal["journal_sha256"]
            or restoration.get("active_raw_sha256") is None
            or restoration.get("binding_raw_sha256") is None
            or restoration.get("state_order_sha256") is None
        ):
            raise DeploymentJournalError(
                "failure recovery authorization requires exact restored journal material"
            )
        body: dict[str, object] = {
            "schema_version": _FAILURE_STEADY_RECOVERY_AUTHORIZATION_SCHEMA,
            "scope": _FAILURE_STEADY_RECOVERY_AUTHORIZATION_SCOPE,
            "attempt_id": journal["attempt"],
            "nonce": journal["nonce"],
            "operation": journal["operation"],
            "failed_phase": journal["phase"],
            "journal_sha256": journal["journal_sha256"],
            "original_pair": journal["original_pair"],
            "candidate": journal["candidate"],
            "state_identity_sha256": journal["state_plan"][
                "state_identity_sha256"
            ],
            "active_pointer_raw_sha256": restoration["active_raw_sha256"],
            "local_prior_binding_raw_sha256": restoration[
                "binding_raw_sha256"
            ],
            "production_state_order_sha256": restoration[
                "state_order_sha256"
            ],
        }
        body["authorization_sha256"] = _identity.identity_sha256(body)
        validated = _validate_failure_steady_recovery_authorization(body)
        record = self.commit_attempt_evidence(
            lock,
            workspace.attempt_id,
            "failure-steady-recovery-authorization",
            _identity.canonical_bytes(validated),
        )
        if record.value != validated:
            raise CompareAndSwapConflict(
                "failure recovery authorization create-through 漂移"
            )
        observed = self._active_failure_steady_recovery_authorization()
        if observed != validated:
            raise CompareAndSwapConflict(
                "failure recovery authorization durable replay 漂移"
            )
        return validated

    def bind_steady_boot_workspace(
        self,
        lock: CrashReleasedFileLock,
    ) -> LockedSteadyBootWorkspace:
        """建立 ordinary steady owner，或消费唯一 durable failure recovery。"""

        self.assert_global_lock(lock)
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if lock._dependent_workspaces:
            raise DeploymentLockBusy(
                "同一 lock epoch 不得混用 transient/steady workspace"
            )
        active_before = self.journals.active_revisions()
        recovery = self._active_failure_steady_recovery_authorization()
        if active_before and recovery is None:
            raise DeploymentJournalError(
                "active deployment journal 缺 failure recovery authorization"
            )
        boot_nonce = secrets.token_hex(24)
        if re.fullmatch(r"[0-9a-f]{48}", boot_nonce) is None:
            raise DeploymentLockBusy("steady boot nonce generator 结果无效")
        workspace = LockedSteadyBootWorkspace(
            persistence=self,
            safe_root=self._safe_root,
            lock=lock,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
            boot_nonce=boot_nonce,
            failure_recovery_authorization=recovery,
            _construction_token=_STEADY_BOOT_WORKSPACE_TOKEN,
        )
        lock._register_workspace(
            workspace,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        try:
            # 注册后再读一次，避免同 epoch 观察跨越 journal/authorization 漂移。
            active_after = self.journals.active_revisions()
            recovery_after = self._active_failure_steady_recovery_authorization()
            if active_after != active_before or recovery_after != recovery:
                raise DeploymentJournalError(
                    "steady workspace 注册期间 journal/recovery authorization 漂移"
                )
            workspace._assert_live()
            return workspace
        except BaseException:
            workspace._close_and_unregister()
            raise

    def _derive_steady_pair_static_material(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
    ) -> Mapping[str, object]:
        """重扫 exact current/state；pending 只允许 durable failure recovery。"""

        self.assert_global_lock(lock)
        if (
            type(workspace) is not LockedSteadyBootWorkspace
            or workspace._persistence is not self
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
        ):
            raise DeploymentLockBusy(
                "steady pair facts 必须绑定同一 persistence/lock/workspace"
            )
        workspace._assert_live()
        active_journals = self.journals.active_revisions()
        recovery = workspace.failure_recovery_authorization
        if active_journals and (
            len(active_journals) != 1
            or recovery is None
            or recovery["journal_sha256"]
            != active_journals[0]["journal_sha256"]
        ):
            raise DeploymentJournalError(
                "active deployment journal 未被 workspace recovery 精确授权"
            )
        if not active_journals and recovery is not None:
            raise DeploymentJournalError(
                "closed journal 不得继续消费 failure recovery authorization"
            )
        active_before = self.read_active_release()
        binding_before = self.read_local_prior_binding()
        if active_before is None:
            raise RetentionPlanningError(
                "steady pair facts 要求 active pointer"
            )
        if binding_before is None:
            raise RetentionPlanningError(
                "ordinary steady admission requires an exact non-null R1/R0 binding"
            )
        binding = binding_before.value
        pair_value = {
            "active": binding["active"],
            "prior": binding["prior"],
        }
        state_identity = _identity.validate_state_identity(
            binding["state_identity"]
        )
        binding_sha256 = binding_before.sha256
        if active_before.value["release"] != pair_value["active"] or (
            pair_value["prior"] is not None
            and pair_value["active"] == pair_value["prior"]
        ):
            raise RetentionPlanningError(
                "steady active pointer/binding pair 不一致或两角色相同"
            )
        if recovery is not None and (
            pair_value != recovery["original_pair"]
            or state_identity["identity_sha256"]
            != recovery["state_identity_sha256"]
        ):
            raise RetentionPlanningError(
                "steady failure recovery pair/state 未绑定 durable authorization"
            )

        inventory = self.release_inventory()
        expected_refs = [pair_value["active"]]
        if pair_value["prior"] is not None:
            expected_refs.append(pair_value["prior"])
        if recovery is not None:
            candidate_hash = recovery["candidate"]["manifest_sha256"]
            if any(entry.manifest_sha256 == candidate_hash for entry in inventory):
                expected_refs.append(recovery["candidate"])
        if len(inventory) != len(expected_refs):
            raise RetentionPlanningError(
                "steady inventory 含未被 current/recovery journal 分类的 release"
            )
        active_entry = self._entry_for_ref(
            pair_value["active"], inventory, label="steady active"
        )
        prior_entry = (
            None
            if pair_value["prior"] is None
            else self._entry_for_ref(
                pair_value["prior"], inventory, label="steady prior"
            )
        )
        if prior_entry is not None and active_entry == prior_entry:
            raise RetentionPlanningError("steady active/prior 解析到同一 closure")
        for reference in expected_refs:
            self._entry_for_ref(reference, inventory, label="steady classified")
        self._assert_release_supports_state(
            self._manifest_for_entry(active_entry),
            state_identity,
            label="steady active",
        )
        if prior_entry is not None:
            self._assert_release_supports_state(
                self._manifest_for_entry(prior_entry),
                state_identity,
                label="steady prior",
            )
        active_after = self.read_active_release()
        binding_after = self.read_local_prior_binding()
        active_journals_after = self.journals.active_revisions()
        recovery_after = self._active_failure_steady_recovery_authorization()
        if (
            active_after is None
            or active_after.raw != active_before.raw
            or (None if binding_after is None else binding_after.raw)
            != (None if binding_before is None else binding_before.raw)
            or active_journals_after != active_journals
            or recovery_after != recovery
        ):
            raise RetentionPlanningError(
                "steady pair facts 双重观察期间 control/journal 漂移"
            )
        retention_material = [
            {
                "role": role,
                "release_id": entry.release_id,
                "manifest_sha256": entry.manifest_sha256,
                "closure_sha256": entry.closure_sha256,
            }
            for role, entry in (
                ("active", active_entry),
                ("prior", prior_entry),
            )
            if entry is not None
        ]
        return {
            "authority_kind": "steady_active",
            "runtime_state_kind": "steady_current",
            "boot_nonce": workspace.boot_nonce,
            "active_release_sha256": active_before.sha256,
            "binding_sha256": binding_sha256,
            "retention_aggregate_sha256": _identity.identity_sha256(
                retention_material
            ),
            "state_identity_sha256": state_identity["identity_sha256"],
            "release": pair_value["active"],
            "prior_release": pair_value["prior"],
        }

    def lock_steady_pair_static_facts(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
    ) -> LockedSteadyPairStaticFacts:
        """派生 pair/state 静态事实；不形成 live closure 或启动授权。"""

        material = self._derive_steady_pair_static_material(lock, workspace)
        facts = LockedSteadyPairStaticFacts(
            persistence=self,
            lock=lock,
            workspace=workspace,
            acquisition_epoch=workspace._acquisition_epoch,
            material=material,
            _construction_token=_LOCKED_STEADY_PAIR_STATIC_FACTS_TOKEN,
        )
        facts._assert_live()
        return facts

    def lock_steady_release_closures(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
    ) -> LockedSteadyReleaseClosures:
        """绑定 steady active/prior 的完整现场闭包；不形成启动授权。"""

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(workspace) is not LockedSteadyBootWorkspace
            or type(facts) is not LockedSteadyPairStaticFacts
            or workspace._persistence is not self
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
            or facts._persistence is not self
            or facts._lock is not lock
            or facts._workspace is not workspace
            or facts._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "steady release closures 必须绑定同一 persistence/lock/workspace/facts epoch"
            )
        material = facts._assert_live()
        closures = LockedSteadyReleaseClosures(
            persistence=self,
            lock=lock,
            workspace=workspace,
            facts=facts,
            material=material,
            _construction_token=_LOCKED_STEADY_RELEASE_CLOSURES_TOKEN,
        )
        workspace._register_steady_release_closures(closures)
        try:
            closures._acquire()
        except BaseException as acquisition_error:
            try:
                closures._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN
                )
            except BaseException as cleanup_error:
                object.__setattr__(workspace, "_state", "closing")
                raise LocalDeploymentPersistenceError(
                    "steady release closure acquisition cleanup 未闭合"
                ) from cleanup_error
            raise acquisition_error
        return closures

    def bind_attempt_workspace(
        self,
        lock: CrashReleasedFileLock,
        attempt_id: str,
        nonce: str,
    ) -> LockedAttemptWorkspace:
        """绑定可 crash-replay 的 fixed tmp workspace，不接受任意路径。"""

        self.assert_global_lock(lock)
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if any(
            type(existing) is LockedSteadyBootWorkspace
            for existing in lock._dependent_workspaces
        ):
            raise DeploymentLockBusy(
                "steady boot workspace live 时不得建立 transient workspace"
            )
        attempt = _safe_identifier(attempt_id, label="attempt workspace attempt")
        stable_nonce = _safe_identifier(nonce, label="attempt workspace nonce")
        component = _safe_identifier(
            f"{attempt}-{stable_nonce}", label="attempt workspace component"
        )
        temporary = self.layout.temporary
        workspace_parent = temporary / _ATTEMPT_WORKSPACE_PARENT
        workspace_path = workspace_parent / component
        guards: list[_BoundDirectory] = []
        try:
            temporary_guard = lock._shared_directory_guard(
                temporary,
                authority_token=self._authority_token,
                acquisition_epoch=acquisition_epoch,
            )
            observed_parent = self._safe_root.preflight(
                workspace_parent,
                expected_kind="directory",
                allow_absent=True,
            )
            if observed_parent is None:
                if self._safe_root.preflight(
                    workspace_parent,
                    expected_kind="directory",
                    allow_absent=True,
                ) is not None:
                    raise UnsafeLocalPath("attempt workspace parent 出现第三值")
                temporary_guard.mkdir(_ATTEMPT_WORKSPACE_PARENT, 0o700)
                temporary_guard.flush()
            self._safe_root.preflight(
                workspace_parent,
                expected_kind="directory",
                allow_absent=False,
            )
            parent_guard = lock._shared_directory_guard(
                workspace_parent,
                authority_token=self._authority_token,
                acquisition_epoch=acquisition_epoch,
            )

            newly_created = False
            observed_workspace = self._safe_root.preflight(
                workspace_path,
                expected_kind="directory",
                allow_absent=True,
            )
            if observed_workspace is None:
                if self._safe_root.preflight(
                    workspace_path,
                    expected_kind="directory",
                    allow_absent=True,
                ) is not None:
                    raise UnsafeLocalPath("attempt workspace mkdir 前出现第三值")
                parent_guard.mkdir(component, 0o700)
                parent_guard.flush()
                newly_created = True
            self._safe_root.preflight(
                workspace_path,
                expected_kind="directory",
                allow_absent=False,
            )
            workspace_guard = _BoundDirectory(self._safe_root, workspace_path)
            workspace_guard.__enter__()
            guards.append(workspace_guard)

            expected_binding = {
                "schema_version": _ATTEMPT_WORKSPACE_SCHEMA,
                "attempt_id": attempt,
                "nonce": stable_nonce,
            }
            expected_raw = _identity.canonical_bytes(expected_binding)
            binding_path = workspace_path / _ATTEMPT_WORKSPACE_BINDING
            if newly_created:
                if self._safe_root.preflight(
                    binding_path, expected_kind="file", allow_absent=True
                ) is not None:
                    raise UnsafeLocalPath("workspace binding 在首次写前出现第三值")
                _write_new_bound_file(
                    workspace_guard,
                    name=_ATTEMPT_WORKSPACE_BINDING,
                    raw=expected_raw,
                    label="attempt workspace binding",
                )
            binding_record = _canonical_read(
                binding_path,
                safe_root=self._safe_root,
                validator=_validate_attempt_workspace_binding,
                label="attempt workspace binding",
            )
            if binding_record is None or binding_record.raw != expected_raw:
                raise UnsafeLocalPath("attempt workspace binding 与 attempt/nonce 不一致")
            workspace = LockedAttemptWorkspace(
                safe_root=self._safe_root,
                lock=lock,
                authority_token=self._authority_token,
                acquisition_epoch=acquisition_epoch,
                attempt_id=attempt,
                nonce=stable_nonce,
                workspace_path=workspace_path,
                guards=guards,
                _construction_token=_ATTEMPT_WORKSPACE_TOKEN,
            )
            lock._register_workspace(
                workspace,
                authority_token=self._authority_token,
                acquisition_epoch=acquisition_epoch,
            )
            return workspace
        except Exception:
            while guards:
                guards.pop().__exit__(None, None, None)
            raise

    def prepare_runtime_canary_layout(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: LockedExactTransientStartAuthorization,
    ) -> None:
        """只从同 epoch transient authority 派生 role-local canary 布局。"""

        self.assert_global_lock(lock)
        workspace._assert_live()
        if (
            workspace._lock is not lock
            or workspace._authority_token is not self._authority_token
            or workspace._safe_root is not self._safe_root
            or type(authorization) is not LockedExactTransientStartAuthorization
        ):
            raise DeploymentLockBusy(
                "runtime canary layout 必须绑定同一 persistence/lock/workspace/epoch"
            )
        try:
            same_epoch = (
                authorization._workspace is workspace
                and authorization._acquisition_epoch
                is workspace._acquisition_epoch
            )
        except AttributeError as error:
            raise DeploymentLockBusy(
                "runtime canary layout authorization 未初始化"
            ) from error
        if not same_epoch:
            raise DeploymentLockBusy(
                "runtime canary layout 必须绑定同一 persistence/lock/workspace/epoch"
            )
        workspace._bind_runtime_canary_layout(authorization)

    @staticmethod
    def _validate_canonical_sqlite_main_bytes(raw: object) -> bytes:
        if type(raw) is not bytes or len(raw) < 512:
            raise UnsafeLocalPath("mutable canary main 必须是非空 SQLite bytes")
        if raw[:16] != b"SQLite format 3\x00":
            raise UnsafeLocalPath("mutable canary main 缺 SQLite header")
        if raw[18:20] != b"\x01\x01":
            raise UnsafeLocalPath(
                "mutable canary main 必须是 rollback-journal read/write format"
            )
        page_size = int.from_bytes(raw[16:18], "big")
        if page_size == 1:
            page_size = 65536
        if (
            page_size < 512
            or page_size > 65536
            or page_size & (page_size - 1)
            or len(raw) % page_size != 0
        ):
            raise UnsafeLocalPath("mutable canary main page geometry 无效")
        connection = sqlite3.connect(":memory:", isolation_level=None)
        try:
            if not hasattr(connection, "deserialize"):
                raise UnsafeLocalPath("当前 SQLite runtime 缺 deserialize")
            connection.deserialize(raw)
            integrity = tuple(
                str(row[0])
                for row in connection.execute("PRAGMA integrity_check").fetchall()
            )
            foreign = tuple(connection.execute("PRAGMA foreign_key_check").fetchall())
            if integrity != ("ok",) or foreign:
                raise UnsafeLocalPath("mutable canary main integrity/foreign key 失败")
        except sqlite3.Error as error:
            raise UnsafeLocalPath("mutable canary main SQLite 解析失败") from error
        finally:
            connection.close()
        return raw

    def create_mutable_canary_sqlite(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        database: str,
        canonical_main_bytes: bytes,
    ) -> LockedMutableCanarySqliteSet:
        """CREATE_NEW 并持续守护 role-local mutable SQLite main。

        产品签名不接受 role、path、root、handle、runtime 或 callback；role 只能来自
        ``prepare_runtime_canary_layout`` 已绑定的 exact transient authority。
        """

        self.assert_global_lock(lock)
        if type(database) is not str or database not in _STATE_SQLITE_DATABASES:
            raise UnsafeLocalPath(
                "mutable canary database 只允许 comments/research_workspace"
            )
        raw = self._validate_canonical_sqlite_main_bytes(canonical_main_bytes)
        workspace._assert_live()
        if (
            workspace._lock is not lock
            or workspace._authority_token is not self._authority_token
            or workspace._safe_root is not self._safe_root
        ):
            raise DeploymentLockBusy(
                "mutable canary SQLite 必须绑定同一 persistence/lock/workspace"
            )
        relative_parts = workspace._mutable_canary_relative_parts(database)
        resource = LockedMutableCanarySqliteSet(
            persistence=self,
            lock=lock,
            workspace=workspace,
            database=database,
            relative_parts=relative_parts,
            initial_main_sha256=hashlib.sha256(raw).hexdigest(),
            _construction_token=_LOCKED_MUTABLE_CANARY_SQLITE_SET_TOKEN,
        )
        # 在首个 creator syscall 前登记整个 resource 与固定 main slot。
        workspace._register_mutable_canary_sqlite_set(resource)
        try:
            resource._acquire(raw)
        except BaseException as acquisition_error:
            if resource._state == "owner_crash_only":
                raise
            try:
                resource._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as cleanup_error:
                workspace._state = "closing"
                raise LocalDeploymentPersistenceError(
                    "mutable canary acquisition cleanup 未闭合"
                ) from cleanup_error
            raise acquisition_error
        return resource

    def lock_state_sqlite_source(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        database: str,
    ) -> LockedStateSqliteSource:
        """派生 fixed-state、non-qualification SQLite source pin。

        产品签名只接受数据库枚举；root/path/URI/env/hook/runtime 均没有入口。
        """

        self.assert_global_lock(lock)
        if type(database) is not str or database not in _STATE_SQLITE_DATABASES:
            raise UnsafeLocalPath(
                "state SQLite database 只允许 comments/research_workspace"
            )
        workspace._assert_live()
        if (
            workspace._lock is not lock
            or workspace._authority_token is not self._authority_token
            or workspace._safe_root is not self._safe_root
        ):
            raise DeploymentLockBusy(
                "state SQLite source 必须绑定同一 persistence/lock/workspace"
            )
        state_guard = lock._shared_directory_guard(
            self.layout.state,
            authority_token=self._authority_token,
            acquisition_epoch=workspace._acquisition_epoch,
        )
        source = LockedStateSqliteSource(
            persistence=self,
            lock=lock,
            workspace=workspace,
            database=database,
            parent_guard=state_guard,
            _construction_token=_LOCKED_STATE_SQLITE_SOURCE_TOKEN,
        )
        workspace._register_state_source(source)
        try:
            source._acquire()
        except BaseException as acquisition_error:
            try:
                source._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as cleanup_error:
                workspace._mark_source_closing()
                raise LocalDeploymentPersistenceError(
                    "state SQLite source acquisition cleanup 未闭合"
                ) from cleanup_error
            raise acquisition_error
        return source

    def lock_exact_release_closures(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> LockedExactReleaseClosures:
        """从当前 attempt 的 latest durable journal 派生 exact release 输入。

        调用者不能传 release ID/hash/ref/path/root/version/URI 或 runtime hook；
        attempt 与 nonce 只来自同一 live workspace。
        """

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            workspace._lock is not lock
            or workspace._authority_token is not self._authority_token
            or workspace._safe_root is not self._safe_root
        ):
            raise DeploymentLockBusy(
                "exact release closures 必须绑定同一 persistence/lock/workspace"
            )
        history = self.journals.replay(workspace.attempt_id)
        latest = history[-1]
        if latest["nonce"] != workspace.nonce:
            raise DeploymentJournalError(
                "latest durable journal nonce 与 workspace 不一致"
            )
        if _journal_is_closed(latest):
            raise DeploymentJournalError(
                "closed deployment attempt 不得派生 exact release closures"
            )
        target_pair = latest["target_pair"]
        operation = str(latest["operation"])
        candidate = target_pair["active"]
        prior = target_pair["prior"]
        role_references: list[tuple[str, Mapping[str, object]]] = [
            ("candidate", candidate)
        ]
        if operation == "bootstrap_first_pair":
            if prior is not None:
                raise DeploymentJournalError(
                    "bootstrap target_pair prior 必须显式 absent"
                )
        else:
            if not isinstance(prior, Mapping):
                raise DeploymentJournalError(
                    "ordinary target_pair 必须含 exact prior"
                )
            role_references.append(("prior", prior))
        closures = LockedExactReleaseClosures(
            persistence=self,
            lock=lock,
            workspace=workspace,
            operation=operation,
            state_identity_sha256=str(
                latest["state_plan"]["state_identity_sha256"]
            ),
            planned_compatibility_sha256=str(
                latest["state_plan"]["compatibility_sha256"]
            ),
            role_references=role_references,
            _construction_token=_LOCKED_EXACT_RELEASE_CLOSURES_TOKEN,
        )
        # 在第一个 fallible directory/file acquisition 之前完成 workspace tracking。
        workspace._register_exact_release_closures(closures)
        try:
            closures._acquire()
        except BaseException as acquisition_error:
            try:
                closures._close_from_workspace(
                    _close_token=_WORKSPACE_RESOURCE_CLOSE_TOKEN,
                )
            except BaseException as cleanup_error:
                workspace._mark_source_closing()
                raise LocalDeploymentPersistenceError(
                    "exact release closures acquisition cleanup 未闭合"
                ) from cleanup_error
            raise acquisition_error
        return closures

    def lock_exact_transient_start_authorization(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        role: str,
    ) -> LockedExactTransientStartAuthorization:
        """从 latest non-terminal journal 派生无调用者路径输入的 start 能力。

        产品调用面只有 closed role 枚举；attempt、nonce、release、SCM identity、
        state identity 与 authorization hash 全部从同一 live workspace 的 durable
        journal 取得。该能力不启动服务且不形成资格。
        """

        self.assert_global_lock(lock)
        if type(role) is not str or role not in {"prior", "candidate", "baseline"}:
            raise DeploymentJournalError(
                "exact transient start role 只允许 prior/candidate/baseline"
            )
        workspace._assert_live()
        if (
            workspace._lock is not lock
            or workspace._authority_token is not self._authority_token
            or workspace._safe_root is not self._safe_root
        ):
            raise DeploymentLockBusy(
                "exact transient start authorization 必须绑定同一 persistence/lock/workspace"
            )
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if workspace._acquisition_epoch is not acquisition_epoch:
            raise DeploymentLockBusy(
                "exact transient start authorization 必须绑定当前 workspace epoch"
            )
        history = self.journals.replay(workspace.attempt_id)
        latest = history[-1]
        if (
            latest["attempt"] != workspace.attempt_id
            or latest["nonce"] != workspace.nonce
        ):
            raise DeploymentJournalError(
                "latest durable journal attempt/nonce 与 transient workspace 不一致"
            )
        _assert_transient_authorization_phase_open(latest)
        start = LockedExactTransientStartAuthorization._select_start(latest, role)
        authorization_sha256 = _transient_start_authorization_sha256(
            latest, start
        )
        evidence = latest["evidence_hashes"]
        evidence_field = _transient_start_authorization_evidence_field(role)
        if (
            not isinstance(evidence, Mapping)
            or evidence.get(evidence_field) != authorization_sha256
        ):
            raise DeploymentJournalError(
                "latest transient start authorization hash/material 不一致"
            )
        return LockedExactTransientStartAuthorization(
            persistence=self,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            journal_sha256=str(latest["journal_sha256"]),
            operation=str(latest["operation"]),
            phase=str(latest["phase"]),
            role=role,
            start_nonce=str(start["start_nonce"]),
            scm_identity_sha256=str(start["scm_identity_sha256"]),
            state_identity_sha256=str(
                latest["state_plan"]["state_identity_sha256"]
            ),
            authorization_sha256=authorization_sha256,
            release_reference=start["release"],
            _construction_token=(
                _LOCKED_EXACT_TRANSIENT_START_AUTHORIZATION_TOKEN
            ),
        )

    def bind_exact_scm_process_observation_input(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: LockedExactTransientStartAuthorization,
        closures: LockedExactReleaseClosures,
    ) -> LockedExactScmProcessObservationInput:
        """闭合 start authorization 与 exact release，不执行任何现场观察。"""

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(authorization) is not LockedExactTransientStartAuthorization
            or type(closures) is not LockedExactReleaseClosures
            or getattr(authorization, "_persistence", None) is not self
            or getattr(authorization, "_workspace", None) is not workspace
            or getattr(authorization, "_acquisition_epoch", None)
            is not acquisition_epoch
            or getattr(closures, "_persistence", None) is not self
            or getattr(closures, "_workspace", None) is not workspace
            or getattr(closures, "_lock", None) is not lock
        ):
            raise DeploymentLockBusy(
                "SCM/process observation input 只接受 exact B2 capability"
            )
        if (
            workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "SCM/process observation input 必须绑定当前 lock/workspace epoch"
            )
        bound = LockedExactScmProcessObservationInput(
            persistence=self,
            lock=lock,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            authorization=authorization,
            closures=closures,
            _construction_token=(
                _LOCKED_EXACT_SCM_PROCESS_OBSERVATION_INPUT_TOKEN
            ),
        )
        bound._assert_live()
        return bound

    def prepare_windows_scm_process_handle_tracking(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        inputs: LockedExactScmProcessObservationInput,
    ) -> LockedWindowsScmProcessHandleTracking:
        """在任何 observer syscall 前登记固定 Windows handle slots。

        该 façade 不接收 service、PID、path、API、hook 或 runtime，也不执行
        现场调用。后续 concrete observer 只能在返回对象已经进入同一 workspace
        tracking 后使用其私有 state-owner syscall seam。
        """

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(inputs) is not LockedExactScmProcessObservationInput
            or getattr(inputs, "_persistence", None) is not self
            or getattr(inputs, "_lock", None) is not lock
            or getattr(inputs, "_workspace", None) is not workspace
            or getattr(inputs, "_acquisition_epoch", None)
            is not acquisition_epoch
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "Windows handle tracking 只接受同 epoch exact observation input"
            )
        inputs._assert_live()
        tracking = LockedWindowsScmProcessHandleTracking(
            persistence=self,
            lock=lock,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            inputs=inputs,
            tracking_kind="transient",
            _construction_token=(
                _LOCKED_WINDOWS_SCM_PROCESS_HANDLE_TRACKING_TOKEN
            ),
        )
        # 在 concrete observer 第一个 fallible syscall 前完成 workspace tracking。
        workspace._register_windows_scm_process_handle_tracking(tracking)
        return tracking

    def prepare_windows_steady_scm_process_handle_tracking(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        inputs: object,
    ) -> LockedWindowsSteadyScmProcessHandleTracking:
        """在 steady observer 首次 syscall 前登记专属固定 handle slots。"""

        from .local_steady_start_authorization import (
            LockedExactSteadyScmProcessObservationInput,
        )

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(workspace) is not LockedSteadyBootWorkspace
            or type(inputs) is not LockedExactSteadyScmProcessObservationInput
            or getattr(inputs, "_workspace", None) is not workspace
            or workspace._persistence is not self
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "steady Windows handle tracking 只接受同 epoch exact steady input"
            )
        inputs._assert_live()
        tracking = LockedWindowsSteadyScmProcessHandleTracking(
            persistence=self,
            lock=lock,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            inputs=inputs,
            tracking_kind="steady",
            _construction_token=(
                _LOCKED_WINDOWS_STEADY_SCM_PROCESS_HANDLE_TRACKING_TOKEN
            ),
        )
        workspace._register_windows_scm_process_handle_tracking(tracking)
        return tracking

    def prepare_windows_writer_lease_handle_tracking(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        scm_tracking: LockedWindowsScmProcessHandleTracking,
    ) -> LockedWindowsWriterLeaseHandleTracking:
        """在 writer observer 首个 syscall 前登记固定 kernel handle slots。"""

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(scm_tracking) is not LockedWindowsScmProcessHandleTracking
            or scm_tracking._persistence is not self
            or scm_tracking._lock is not lock
            or scm_tracking._workspace is not workspace
            or scm_tracking._acquisition_epoch is not acquisition_epoch
            or scm_tracking._state != "live"
            or scm_tracking
            not in workspace._windows_scm_process_handle_tracking
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "writer lease tracking 只接受同 epoch live SCM tracking"
            )
        scm_tracking._assert_context(states={"live"})
        tracking = LockedWindowsWriterLeaseHandleTracking(
            persistence=self,
            lock=lock,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            scm_tracking=scm_tracking,
            tracking_kind="transient",
            _construction_token=(
                _LOCKED_WINDOWS_WRITER_LEASE_HANDLE_TRACKING_TOKEN
            ),
        )
        workspace._register_windows_writer_lease_handle_tracking(tracking)
        return tracking

    def prepare_windows_steady_writer_lease_handle_tracking(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        scm_tracking: LockedWindowsSteadyScmProcessHandleTracking,
    ) -> LockedWindowsSteadyWriterLeaseHandleTracking:
        """在 steady writer observer 首个 syscall 前登记专属 handle slots。"""

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(scm_tracking)
            is not LockedWindowsSteadyScmProcessHandleTracking
            or scm_tracking._persistence is not self
            or scm_tracking._lock is not lock
            or scm_tracking._workspace is not workspace
            or scm_tracking._acquisition_epoch is not acquisition_epoch
            or scm_tracking._state != "live"
            or scm_tracking
            not in workspace._steady_windows_scm_process_handle_tracking
            or workspace._persistence is not self
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "steady writer tracking 只接受同 epoch live steady SCM tracking"
            )
        scm_tracking._assert_context(states={"live"})
        tracking = LockedWindowsSteadyWriterLeaseHandleTracking(
            persistence=self,
            lock=lock,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            scm_tracking=scm_tracking,
            tracking_kind="steady",
            _construction_token=(
                _LOCKED_WINDOWS_STEADY_WRITER_LEASE_HANDLE_TRACKING_TOKEN
            ),
        )
        workspace._register_windows_writer_lease_handle_tracking(tracking)
        return tracking

    def commit_attempt_evidence(
        self,
        lock: CrashReleasedFileLock,
        attempt_id: str,
        evidence_id: str,
        canonical_bytes: bytes,
    ) -> CanonicalJsonRecord:
        """以 expected-or-exact create-through 语义提交 canonical evidence。"""

        return self._commit_attempt_evidence(
            lock,
            attempt_id,
            evidence_id,
            canonical_bytes,
            allow_existing_exact=True,
        )

    def _checkpoint_runtime_qualification_artifacts(
        self,
        attempt_id: str,
        role: str,
        *,
        expected_raw: bytes | None,
    ) -> None:
        from .local_runtime_qualification_evidence import (
            LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
            LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
            LocalRuntimeQualificationEvidenceError,
            parse_local_runtime_qualification_evidence_bytes,
        )

        attempt = _safe_identifier(attempt_id, label="qualification artifact attempt")
        if role not in {"prior", "candidate", "baseline"}:
            raise DeploymentJournalError("qualification artifact role 无效")
        directory = self.layout.journals / f"{attempt}.evidence"
        observed_directory = self._safe_root.preflight(
            directory,
            expected_kind="directory",
            allow_absent=True,
        )
        if observed_directory is None:
            if expected_raw is not None:
                raise CompareAndSwapConflict("qualification artifact 持久后缺失")
            return
        self.journals._validate_evidence_directory(directory, attempt=attempt)
        target_name = f"runtime-qualification-{role}.json"
        target_key = unicodedata.normalize("NFKC", target_name).casefold()
        current_found = False
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            entry_key = unicodedata.normalize("NFKC", entry.name).casefold()
            if entry_key == target_key and entry.name != target_name:
                raise CompareAndSwapConflict(
                    "qualification artifact 存在 case/NFKC alias"
                )
            record = _canonical_read(
                directory / entry.name,
                safe_root=self._safe_root,
                validator=_validate_attempt_evidence,
                label="runtime qualification artifact checkpoint",
            )
            if record is None:
                raise CompareAndSwapConflict("qualification artifact 枚举后消失")
            document = record.value
            reserved = (
                document.get("schema_version")
                == LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA
                or document.get("scope")
                == LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE
            )
            if not reserved and entry.name != target_name:
                continue
            if entry.name == target_name and expected_raw is None:
                raise CompareAndSwapConflict(
                    "qualification artifact 在 one-shot consume 前必须 absent"
                )
            try:
                evidence = parse_local_runtime_qualification_evidence_bytes(record.raw)
            except LocalRuntimeQualificationEvidenceError as error:
                raise CompareAndSwapConflict(
                    "reserved qualification schema/scope artifact 不闭合"
                ) from error
            evidence_document = evidence.as_dict()
            evidence_role = str(evidence_document["role"])
            expected_name = f"runtime-qualification-{evidence_role}.json"
            if (
                entry.name != expected_name
                or evidence_document["attempt_id"] != attempt
            ):
                raise CompareAndSwapConflict(
                    "qualification artifact schema/scope 出现错名或 foreign attempt alias"
                )
            if evidence_role == role:
                if expected_raw is None or record.raw != expected_raw:
                    raise CompareAndSwapConflict(
                        "qualification artifact 不是当前 frozen aggregate"
                    )
                current_found = True
            else:
                historical_field = (
                    "prior_runtime_qualification_sha256"
                    if evidence_role == "prior"
                    else "candidate_runtime_qualification_sha256"
                )
                historical_phase = (
                    "prior_verified"
                    if evidence_role == "prior"
                    else "candidate_verified"
                )
                history = self.journals.replay(attempt)
                if not any(
                    revision["phase"] == historical_phase
                    and revision["evidence_hashes"].get(historical_field)
                    == evidence.aggregate_sha256
                    for revision in history
                ):
                    raise CompareAndSwapConflict(
                        "foreign-role qualification artifact 未绑定历史 verified revision"
                    )
        if expected_raw is not None and not current_found:
            raise CompareAndSwapConflict("qualification artifact 未在固定位置闭合")

    def _commit_attempt_evidence(
        self,
        lock: CrashReleasedFileLock,
        attempt_id: str,
        evidence_id: str,
        canonical_bytes: bytes,
        *,
        allow_existing_exact: bool,
    ) -> CanonicalJsonRecord:
        """State-owning create seam; formal qualification forbids all replay."""

        self.assert_global_lock(lock)
        attempt = _safe_identifier(attempt_id, label="attempt evidence attempt")
        evidence = _safe_identifier(evidence_id, label="attempt evidence id")
        if not isinstance(canonical_bytes, bytes):
            raise LocalDeploymentPersistenceError("attempt evidence 必须是 bytes")
        try:
            parsed = json.loads(canonical_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LocalDeploymentPersistenceError(
                "attempt evidence 不是 UTF-8 JSON"
            ) from error
        validated = _validate_attempt_evidence(parsed)
        if _identity.canonical_bytes(validated) != canonical_bytes:
            raise LocalDeploymentPersistenceError(
                "attempt evidence 不是 exact canonical JSON"
            )

        directory = self.layout.journals / f"{attempt}.evidence"
        target = directory / f"{evidence}.json"
        with _BoundDirectory(self._safe_root, self.layout.journals) as journal_guard:
            observed_directory = self._safe_root.preflight(
                directory,
                expected_kind="directory",
                allow_absent=True,
            )
            if observed_directory is None:
                if self._safe_root.preflight(
                    directory,
                    expected_kind="directory",
                    allow_absent=True,
                ) is not None:
                    raise UnsafeLocalPath("attempt evidence directory 出现第三值")
                try:
                    journal_guard.mkdir(directory.name, 0o700)
                    journal_guard.flush()
                except OSError as error:
                    raise UnsafeLocalPath(
                        "无法排他创建 attempt evidence directory"
                    ) from error
            self._safe_root.preflight(
                directory,
                expected_kind="directory",
                allow_absent=False,
            )
            with _BoundDirectory(self._safe_root, directory) as evidence_guard:
                observed = _canonical_read(
                    target,
                    safe_root=self._safe_root,
                    validator=_validate_attempt_evidence,
                    label="attempt evidence",
                )
                if observed is not None:
                    if allow_existing_exact and observed.raw == canonical_bytes:
                        return observed
                    raise CompareAndSwapConflict(
                        "attempt evidence 已存在，当前 seam 禁止重放或第三值"
                    )
                _write_new_bound_file(
                    evidence_guard,
                    name=target.name,
                    raw=canonical_bytes,
                    label="attempt evidence",
                )
                confirmed = _canonical_read(
                    target,
                    safe_root=self._safe_root,
                    validator=_validate_attempt_evidence,
                    label="attempt evidence",
                )
                if confirmed is None or confirmed.raw != canonical_bytes:
                    raise CompareAndSwapConflict(
                        "attempt evidence create-through 后不是 desired"
                    )
                return confirmed

    def consume_runtime_qualification_and_advance(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        qualification: object,
        expected_start_authorized_revision: int,
    ) -> LockedVerifiedPhaseCasAuthorization:
        """Persist one formal aggregate and CAS the adjacent verified revision."""

        from .local_runtime_qualification import LockedLocalRuntimeQualification

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(qualification) is not LockedLocalRuntimeQualification
            or type(expected_start_authorized_revision) is not int
            or expected_start_authorized_revision < 0
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "runtime qualification consume 只接受同 epoch exact capability"
            )
        aggregate = qualification._prepare_b2_consume(  # noqa: SLF001
            self,
            lock,
            workspace,
        )
        document = aggregate.as_dict()
        role = str(document["role"])
        expected_phase = (
            "prior_start_authorized"
            if role == "prior"
            else "candidate_start_authorized"
        )
        next_phase = "prior_verified" if role == "prior" else "candidate_verified"
        evidence_field = (
            "prior_runtime_qualification_sha256"
            if role == "prior"
            else "candidate_runtime_qualification_sha256"
        )
        if role not in {"prior", "candidate", "baseline"}:
            raise DeploymentJournalError("runtime qualification role 不属于闭合枚举")
        if (
            document["production_state_before_order_sha256"]
            != document["production_state_after_order_sha256"]
        ):
            raise DeploymentJournalError(
                "runtime qualification production state before/after 不一致"
            )
        canary = qualification._observation._canary  # noqa: SLF001
        state_sources = getattr(canary, "_sources", None)
        if type(state_sources) is not dict:
            raise DeploymentLockBusy(
                "runtime qualification 缺少同链 live production state sources"
            )
        if (
            _locked_production_state_order_sha256(
                state_sources,
                persistence=self,
                workspace=workspace,
            )
            != document["production_state_after_order_sha256"]
        ):
            raise DeploymentJournalError(
                "runtime qualification live production state seal 漂移"
            )
        history = self.journals.replay(workspace.attempt_id)
        latest = history[-1]
        if (
            latest["attempt"] != workspace.attempt_id
            or latest["nonce"] != workspace.nonce
            or latest["revision"] != expected_start_authorized_revision
            or latest["phase"] != expected_phase
            or latest["operation"] != document["operation"]
            or latest["state_plan"]["state_identity_sha256"]
            != document["state_identity_sha256"]
        ):
            raise DeploymentJournalError(
                "runtime qualification 未绑定 expected latest start-authorized revision"
            )
        self._verified_phase_current_records(latest, role=role)
        authorization = canary._authorization  # noqa: SLF001
        if (
            type(authorization) is not LockedExactTransientStartAuthorization
            or authorization._persistence is not self
            or authorization._workspace is not workspace
            or authorization._acquisition_epoch is not acquisition_epoch
            or authorization._journal_sha256 != latest["journal_sha256"]
            or authorization._authorization_sha256
            != document["authorization_sha256"]
            or authorization._role != role
        ):
            raise DeploymentLockBusy(
                "runtime qualification 与 transient authorization owner/material 漂移"
            )

        evidence_id = f"runtime-qualification-{role}"
        self._checkpoint_runtime_qualification_artifacts(
            workspace.attempt_id,
            role,
            expected_raw=None,
        )
        self._commit_attempt_evidence(
            lock,
            workspace.attempt_id,
            evidence_id,
            aggregate.canonical_bytes(),
            allow_existing_exact=False,
        )
        self._checkpoint_runtime_qualification_artifacts(
            workspace.attempt_id,
            role,
            expected_raw=aggregate.canonical_bytes(),
        )
        confirmed = qualification._prepare_b2_consume(  # noqa: SLF001
            self,
            lock,
            workspace,
        )
        if confirmed.canonical_bytes() != aggregate.canonical_bytes():
            raise DeploymentJournalError(
                "runtime qualification artifact 写入后 live aggregate 漂移"
            )
        self._checkpoint_runtime_qualification_artifacts(
            workspace.attempt_id,
            role,
            expected_raw=aggregate.canonical_bytes(),
        )
        latest_after_evidence = self.journals.replay(workspace.attempt_id)[-1]
        if latest_after_evidence != latest:
            raise DeploymentJournalError(
                "runtime qualification artifact 写入窗口 journal 漂移"
            )

        next_journal = json.loads(
            _identity.canonical_bytes(latest_after_evidence).decode("utf-8")
        )
        if type(next_journal) is not dict:
            raise DeploymentJournalError("next verified journal clone 类型漂移")
        next_journal["revision"] = int(latest_after_evidence["revision"]) + 1
        next_journal["phase"] = next_phase
        next_journal["previous_journal_sha256"] = latest_after_evidence[
            "journal_sha256"
        ]
        previous_updated = _timestamp(
            latest_after_evidence["timestamps"]["updated_at"],
            label="latest journal updated_at",
        )
        updated = datetime.now().astimezone()
        if updated < previous_updated:
            updated = previous_updated
        next_journal["timestamps"]["updated_at"] = updated.isoformat(
            timespec="seconds"
        )
        next_journal["evidence_hashes"][evidence_field] = (
            aggregate.aggregate_sha256
        )
        next_journal.pop("journal_sha256", None)
        next_journal["journal_sha256"] = _identity.identity_sha256(next_journal)
        try:
            appended = self.journals.append(next_journal, lock=lock)
        except BaseException as append_error:
            try:
                replayed_after_error = self.journals.replay(workspace.attempt_id)
            except BaseException as replay_error:
                raise DeploymentJournalError(
                    "verified revision append 结果不明且无法重放"
                ) from replay_error
            if replayed_after_error[-1] != validate_deployment_journal(next_journal):
                raise DeploymentJournalError(
                    "verified revision append 失败且 durable latest 不是 expected"
                ) from append_error
            appended = replayed_after_error[-1]
        if (
            appended["phase"] != next_phase
            or appended["previous_journal_sha256"]
            != latest_after_evidence["journal_sha256"]
            or appended["evidence_hashes"][evidence_field]
            != aggregate.aggregate_sha256
        ):
            raise DeploymentJournalError("verified revision 持久结果不闭合")

        active, binding = self._verified_phase_current_records(appended, role=role)
        next_action = {
            "prior": "active_pointer_cas",
            "candidate": "local_prior_binding_cas",
            "baseline": "bootstrap_terminal_receipt",
        }[role]
        verified = LockedVerifiedPhaseCasAuthorization(
            persistence=self,
            workspace=workspace,
            acquisition_epoch=acquisition_epoch,
            journal_sha256=str(appended["journal_sha256"]),
            phase=next_phase,
            role=role,
            qualification_sha256=aggregate.aggregate_sha256,
            active_raw=None if active is None else active.raw,
            binding_raw=None if binding is None else binding.raw,
            next_action=next_action,
            state_sources=state_sources,
            production_state_order_sha256=str(
                document["production_state_after_order_sha256"]
            ),
            closures=canary._closures,  # noqa: SLF001 - same live chain.
            release_compatibility_sha256=str(
                document["release_compatibility_sha256"]
            ),
            release_closure_sha256=str(
                document["release_closure_sha256"]
            ),
            _construction_token=(
                _LOCKED_VERIFIED_PHASE_CAS_AUTHORIZATION_TOKEN
            ),
        )
        qualification._mark_consumed_from_b2(  # noqa: SLF001
            self,
            lock,
            workspace,
            aggregate.aggregate_sha256,
        )
        verified._assert_live()
        return verified

    def commit_bootstrap_pointer_cas(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> CompareAndSwapResult:
        """Commit the sole bootstrap ``active: absent -> R0`` CAS.

        The expected and desired records are derived only from the durable v4
        journal.  The evidence has no clock field, so a crash after the control
        write but before the adjacent journal append can replay exact bytes.
        """

        self.assert_global_lock(lock)
        workspace._assert_live()
        latest = self.journals.replay(workspace.attempt_id)[-1]
        if (
            latest["attempt"] != workspace.attempt_id
            or latest["nonce"] != workspace.nonce
            or latest["operation"] != "bootstrap_first_pair"
            or latest["phase"] not in {
                "state_expand_applied",
                "pointer_cas_committed",
            }
        ):
            raise DeploymentJournalError(
                "bootstrap pointer CAS requires state-applied bootstrap journal"
            )
        if self.read_local_prior_binding() is not None:
            raise CompareAndSwapConflict(
                "bootstrap pointer CAS requires absent local-prior binding"
            )
        desired = _identity.validate_active_release(
            {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": latest["pointer_cas"]["desired"],
            }
        )
        desired_raw = _identity.canonical_bytes(desired)
        observed = self.read_active_release()
        observed_raw = None if observed is None else observed.raw
        if observed_raw not in {None, desired_raw}:
            raise CompareAndSwapConflict(
                "bootstrap pointer is neither absent nor exact desired R0"
            )
        source_revision = (
            latest
            if latest["phase"] == "state_expand_applied"
            else self.journals.replay(workspace.attempt_id)[-2]
        )
        if source_revision["phase"] != "state_expand_applied":
            raise DeploymentJournalError(
                "bootstrap pointer CAS lacks adjacent state-applied revision"
            )
        observation: dict[str, object] = {
            "schema_version": _BOOTSTRAP_POINTER_CAS_OBSERVATION_SCHEMA,
            "scope": _BOOTSTRAP_POINTER_CAS_OBSERVATION_SCOPE,
            "attempt_id": workspace.attempt_id,
            "nonce": workspace.nonce,
            "operation": "bootstrap_first_pair",
            "source_journal_sha256": source_revision["journal_sha256"],
            "expected": None,
            "desired": desired,
            "result": {
                "status": "desired_durable",
                "expected_sha256": None,
                "desired_sha256": hashlib.sha256(desired_raw).hexdigest(),
            },
        }
        observation["observation_sha256"] = _identity.identity_sha256(
            observation
        )
        observation_raw = _identity.canonical_bytes(observation)
        if latest["phase"] == "pointer_cas_committed":
            evidence_path = (
                self.layout.journals
                / f"{workspace.attempt_id}.evidence"
                / "bootstrap-pointer-cas.json"
            )
            evidence = _canonical_read(
                evidence_path,
                safe_root=self._safe_root,
                validator=_validate_attempt_evidence,
                label="bootstrap pointer CAS evidence",
            )
            if (
                observed_raw != desired_raw
                or evidence is None
                or evidence.raw != observation_raw
                or latest["evidence_hashes"]["pointer_cas_observation_sha256"]
                != observation["observation_sha256"]
            ):
                raise CompareAndSwapConflict(
                    "bootstrap pointer CAS replay is not exact/durable"
                )
            return CompareAndSwapResult("already_desired", observed.sha256)

        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        control_parent = lock._shared_directory_guard(
            self.layout.control,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        temporary_parent = lock._shared_directory_guard(
            self.layout.temporary,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        if observed_raw is None:
            result = self._active.compare_and_swap(
                lock=lock,
                expected=None,
                desired=desired,
                target_parent=control_parent,
                temporary_parent=temporary_parent,
            )
        else:
            result = CompareAndSwapResult("already_desired", observed.sha256)
        confirmed = self.read_active_release()
        if confirmed is None or confirmed.raw != desired_raw:
            raise CompareAndSwapConflict(
                "bootstrap pointer CAS desired R0 is not durable"
            )
        self._commit_attempt_evidence(
            lock,
            workspace.attempt_id,
            "bootstrap-pointer-cas",
            observation_raw,
            allow_existing_exact=True,
        )
        replayed = self.journals.replay(workspace.attempt_id)[-1]
        if replayed != latest:
            raise DeploymentJournalError(
                "bootstrap pointer CAS journal drifted before adjacent append"
            )
        next_journal = json.loads(
            _identity.canonical_bytes(latest).decode("utf-8")
        )
        next_journal["revision"] = int(latest["revision"]) + 1
        next_journal["phase"] = "pointer_cas_committed"
        next_journal["previous_journal_sha256"] = latest["journal_sha256"]
        # Derive the adjacent revision solely from durable material.  If the
        # pointer/evidence commit succeeded and the process died around the
        # journal append, a fresh process must regenerate identical bytes.
        next_journal["timestamps"]["updated_at"] = latest["timestamps"][
            "updated_at"
        ]
        next_journal["evidence_hashes"][
            "pointer_cas_observation_sha256"
        ] = observation["observation_sha256"]
        next_journal.pop("journal_sha256", None)
        next_journal["journal_sha256"] = _identity.identity_sha256(
            next_journal
        )
        try:
            self.journals.append(next_journal, lock=lock)
        except BaseException as append_error:
            try:
                replayed_after_error = self.journals.replay(
                    workspace.attempt_id
                )
            except BaseException as replay_error:
                raise DeploymentJournalError(
                    "bootstrap pointer journal append outcome is ambiguous"
                ) from replay_error
            if replayed_after_error[-1] != validate_deployment_journal(
                next_journal
            ):
                raise DeploymentJournalError(
                    "bootstrap pointer append failed without exact durable revision"
                ) from append_error
        return result

    def consume_bootstrap_terminal(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: LockedVerifiedPhaseCasAuthorization,
        state_identity: Mapping[str, object],
        ingress_closed_sha256: str,
        legacy_c_writer_fence_sha256: str,
    ) -> Mapping[str, object]:
        """Consume a live R0 qualification into the bootstrap terminal."""

        self.assert_global_lock(lock)
        workspace._assert_live()
        if (
            type(authorization) is not LockedVerifiedPhaseCasAuthorization
            or authorization._persistence is not self
            or authorization._workspace is not workspace
            or authorization._role != "baseline"
            or authorization._next_action != "bootstrap_terminal_receipt"
        ):
            raise DeploymentLockBusy(
                "bootstrap terminal requires the live baseline qualification"
            )
        latest = authorization._assert_live()
        if (
            latest["operation"] != "bootstrap_first_pair"
            or latest["phase"] != "candidate_verified"
        ):
            raise DeploymentJournalError(
                "bootstrap terminal requires adjacent candidate_verified revision"
            )
        state = _identity.validate_state_identity(state_identity)
        if (
            state["identity_sha256"]
            != latest["state_plan"]["state_identity_sha256"]
        ):
            raise DeploymentJournalError(
                "bootstrap terminal state identity differs from durable plan"
            )
        ingress_hash = _sha256(
            ingress_closed_sha256,
            label="bootstrap ingress closed evidence",
        )
        legacy_hash = _sha256(
            legacy_c_writer_fence_sha256,
            label="bootstrap legacy C writer fence evidence",
        )
        active = self.read_active_release()
        binding = self.read_local_prior_binding()
        if (
            active is None
            or active.value["release"] != latest["candidate"]
            or binding is not None
        ):
            raise CompareAndSwapConflict(
                "bootstrap terminal control pair is not exact R0/null"
            )
        proof = {
            "ingress_status": "closed",
            "legacy_c_writer_status": "fenced",
            "r0_live": latest["candidate"],
            "writer_fence_sha256": _identity.identity_sha256(
                {
                    "ingress_closed_sha256": ingress_hash,
                    "legacy_c_writer_fence_sha256": legacy_hash,
                    "runtime_qualification_sha256": authorization._qualification_sha256,
                    "r0": latest["candidate"],
                }
            ),
        }
        pair = latest["target_pair"]
        receipt_body: dict[str, object] = {
            "schema_version": _identity.ACTIVATION_RECEIPT_SCHEMA,
            "receipt_id": latest["reserved_receipt_ids"]["activation"],
            "attempt_id": latest["attempt"],
            "recorded_at": latest["timestamps"]["updated_at"],
            "authority": "evidence_only",
            "operation": "bootstrap_first_pair",
            "original": {
                "active_pointer_status": "absent",
                "local_prior_binding_status": "absent",
            },
            "pair": pair,
            "state_identity": state,
            "proof": proof,
            "result": {
                "status": "bootstrapped",
                "pair_sha256": _identity.identity_sha256(pair),
                "state_identity_sha256": state["identity_sha256"],
                "proof_sha256": _identity.identity_sha256(proof),
            },
        }
        receipt_body["receipt_sha256"] = _identity.identity_sha256(
            receipt_body
        )
        receipt = _identity.validate_activation_receipt(receipt_body)
        self.commit_local_receipt(lock=lock, receipt=receipt)
        authorization._assert_live()
        terminal = json.loads(
            _identity.canonical_bytes(latest).decode("utf-8")
        )
        terminal["revision"] = int(latest["revision"]) + 1
        terminal["phase"] = "terminal_receipt_committed"
        terminal["previous_journal_sha256"] = latest["journal_sha256"]
        # Receipt commit and journal append are separate atomic writes.  Keep
        # the terminal bytes deterministic so a crash between them can replay.
        terminal["timestamps"]["updated_at"] = latest["timestamps"][
            "updated_at"
        ]
        terminal["evidence_hashes"][
            "bootstrap_ingress_closed_sha256"
        ] = ingress_hash
        terminal["evidence_hashes"][
            "bootstrap_legacy_c_writer_fence_sha256"
        ] = legacy_hash
        terminal["terminal_receipt"] = {
            "kind": "activation",
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
        }
        terminal.pop("journal_sha256", None)
        terminal["journal_sha256"] = _identity.identity_sha256(terminal)
        try:
            appended = self.journals.append(terminal, lock=lock)
        except BaseException as append_error:
            try:
                replayed_after_error = self.journals.replay(
                    workspace.attempt_id
                )
            except BaseException as replay_error:
                raise DeploymentJournalError(
                    "bootstrap terminal journal append outcome is ambiguous"
                ) from replay_error
            if replayed_after_error[-1] != validate_deployment_journal(
                terminal
            ):
                raise DeploymentJournalError(
                    "bootstrap terminal append failed without exact durable revision"
                ) from append_error
            appended = replayed_after_error[-1]
        authorization._mark_consumed_from_b2(
            self,
            lock,
            workspace,
            str(latest["journal_sha256"]),
        )
        return appended

    def _verified_phase_current_records(
        self,
        journal: Mapping[str, object],
        *,
        role: str,
        allow_cas_already_desired: bool = False,
    ) -> tuple[CanonicalJsonRecord | None, CanonicalJsonRecord | None]:
        active = self.read_active_release()
        binding = self.read_local_prior_binding()
        expected_release = (
            journal["pointer_cas"]["expected"]
            if role == "prior"
            else journal["pointer_cas"]["desired"]
        )
        allowed_releases = [expected_release]
        if role == "prior" and allow_cas_already_desired:
            allowed_releases.append(journal["pointer_cas"]["desired"])
        if (
            active is None
            or active.value.get("release") not in allowed_releases
        ):
            raise CompareAndSwapConflict(
                "verified phase current active pointer 不是该阶段 expected/desired release"
            )
        expected_binding_sha256 = journal["binding_cas"][
            "expected_binding_sha256"
        ]
        desired_binding_sha256 = journal["binding_cas"][
            "desired_binding_sha256"
        ]
        allowed_binding_sha256 = [expected_binding_sha256]
        if role == "candidate" and allow_cas_already_desired:
            allowed_binding_sha256.append(desired_binding_sha256)
        if binding is None:
            if None not in allowed_binding_sha256:
                raise CompareAndSwapConflict(
                    "verified phase 要求 current prior binding present"
                )
        elif binding.value.get("binding_sha256") not in allowed_binding_sha256:
            raise CompareAndSwapConflict(
                "verified phase current prior binding 不是 expected/desired binding"
            )
        return active, binding

    def lock_verified_phase_cas_authorization(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        role: str,
        closures: LockedExactReleaseClosures,
    ) -> LockedVerifiedPhaseCasAuthorization:
        """Replay a narrow verified-phase CAS authority, never qualification."""

        from .local_runtime_qualification_evidence import (
            LocalRuntimeQualificationEvidenceError,
            parse_local_runtime_qualification_evidence_bytes,
        )
        from .local_exact_release_compatibility import (
            build_exact_release_compatibility_evidence,
        )

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(role) is not str
            or role not in {"prior", "candidate", "baseline"}
            or type(closures) is not LockedExactReleaseClosures
            or closures._persistence is not self
            or closures._lock is not lock
            or closures._workspace is not workspace
            or closures._state != "live"
            or workspace._acquisition_epoch is not acquisition_epoch
        ):
            raise DeploymentLockBusy(
                "verified replay 只接受同 epoch exact release closures"
            )
        latest = self.journals.replay(workspace.attempt_id)[-1]
        expected_phase = "prior_verified" if role == "prior" else "candidate_verified"
        evidence_field = (
            "prior_runtime_qualification_sha256"
            if role == "prior"
            else "candidate_runtime_qualification_sha256"
        )
        qualification_sha256 = latest["evidence_hashes"].get(evidence_field)
        if (
            latest["attempt"] != workspace.attempt_id
            or latest["nonce"] != workspace.nonce
            or latest["phase"] != expected_phase
            or type(qualification_sha256) is not str
        ):
            raise DeploymentJournalError(
                "verified replay latest 不是 exact role verified revision"
            )
        target = (
            self.layout.journals
            / f"{workspace.attempt_id}.evidence"
            / f"runtime-qualification-{role}.json"
        )
        record = _canonical_read(
            target,
            safe_root=self._safe_root,
            validator=_validate_attempt_evidence,
            label="verified replay runtime qualification evidence",
        )
        if record is None:
            raise DeploymentJournalError("verified replay 缺固定 qualification evidence")
        try:
            aggregate = parse_local_runtime_qualification_evidence_bytes(record.raw)
        except LocalRuntimeQualificationEvidenceError as error:
            raise DeploymentJournalError(
                "verified replay qualification evidence 不闭合"
            ) from error
        aggregate_document = aggregate.as_dict()
        start = LockedExactTransientStartAuthorization._select_start(latest, role)
        if (
            aggregate.aggregate_sha256 != qualification_sha256
            or aggregate_document["attempt_id"] != workspace.attempt_id
            or aggregate_document["nonce"] != workspace.nonce
            or aggregate_document["operation"] != latest["operation"]
            or aggregate_document["role"] != role
            or aggregate_document["start_nonce"] != start["start_nonce"]
            or aggregate_document["authorization_sha256"]
            != _transient_start_authorization_sha256(latest, start)
            or aggregate_document["state_identity_sha256"]
            != latest["state_plan"]["state_identity_sha256"]
            or aggregate_document["production_state_before_order_sha256"]
            != aggregate_document["production_state_after_order_sha256"]
        ):
            raise DeploymentJournalError(
                "verified replay aggregate 未 exact 绑定 durable revision"
            )
        self._checkpoint_runtime_qualification_artifacts(
            workspace.attempt_id,
            role,
            expected_raw=record.raw,
        )
        metadata = closures.metadata()
        compatibility = build_exact_release_compatibility_evidence(closures)
        closure_role = "prior" if role == "prior" else "candidate"
        closure_roles = metadata.get("roles")
        role_metadata = (
            closure_roles.get(closure_role)
            if type(closure_roles) is dict
            else None
        )
        if (
            metadata.get("operation") != latest["operation"]
            or metadata.get("attempt_id") != workspace.attempt_id
            or metadata.get("nonce") != workspace.nonce
            or metadata.get("state_identity_sha256")
            != latest["state_plan"]["state_identity_sha256"]
            or metadata.get("planned_compatibility_sha256")
            != latest["state_plan"]["compatibility_sha256"]
            or _identity.identity_sha256(metadata)
            != aggregate_document["release_closure_sha256"]
            or compatibility.aggregate_sha256
            != aggregate_document["release_compatibility_sha256"]
            or type(role_metadata) is not dict
            or role_metadata.get("release_id") != start["release"]["release_id"]
            or role_metadata.get("manifest_sha256")
            != start["release"]["manifest_sha256"]
        ):
            raise DeploymentJournalError(
                "verified replay exact release closure 未绑定 role/start/state"
            )
        active, binding = self._verified_phase_current_records(
            latest,
            role=role,
            allow_cas_already_desired=True,
        )
        state_sources: dict[str, LockedStateSqliteSource] = {}
        try:
            for database in _STATE_SQLITE_DATABASES:
                state_sources[database] = self.lock_state_sqlite_source(
                    lock, workspace, database
                )
            production_state_order_sha256 = (
                _locked_production_state_order_sha256(
                    state_sources,
                    persistence=self,
                    workspace=workspace,
                )
            )
            if production_state_order_sha256 != aggregate_document[
                "production_state_after_order_sha256"
            ]:
                raise DeploymentJournalError(
                    "verified replay newly observed production state seal 漂移"
                )
            next_action = {
                "prior": "active_pointer_cas",
                "candidate": "local_prior_binding_cas",
                "baseline": "bootstrap_terminal_receipt",
            }[role]
            authorization = LockedVerifiedPhaseCasAuthorization(
                persistence=self,
                workspace=workspace,
                acquisition_epoch=acquisition_epoch,
                journal_sha256=str(latest["journal_sha256"]),
                phase=expected_phase,
                role=role,
                qualification_sha256=str(qualification_sha256),
                active_raw=None if active is None else active.raw,
                binding_raw=None if binding is None else binding.raw,
                next_action=next_action,
                state_sources=state_sources,
                production_state_order_sha256=(
                    production_state_order_sha256
                ),
                closures=closures,
                release_compatibility_sha256=str(
                    aggregate_document["release_compatibility_sha256"]
                ),
                release_closure_sha256=str(
                    aggregate_document["release_closure_sha256"]
                ),
                _construction_token=(
                    _LOCKED_VERIFIED_PHASE_CAS_AUTHORIZATION_TOKEN
                ),
            )
            authorization._assert_live()
            return authorization
        except BaseException:
            close_error: BaseException | None = None
            for source in reversed(tuple(state_sources.values())):
                try:
                    source.close()
                except BaseException as error:
                    if close_error is None:
                        close_error = error
            if close_error is not None:
                raise LocalDeploymentPersistenceError(
                    "verified replay state source cleanup 未闭合"
                ) from close_error
            raise

    def _read_verified_phase_cas_observation(
        self,
        attempt_id: str,
        role: str,
    ) -> CanonicalJsonRecord | None:
        attempt = _safe_identifier(
            attempt_id,
            label="verified-phase CAS observation attempt",
        )
        if role not in {"prior", "candidate"}:
            raise DeploymentJournalError(
                "verified-phase CAS observation role 无效"
            )
        directory = self.layout.journals / f"{attempt}.evidence"
        observed_directory = self._safe_root.preflight(
            directory,
            expected_kind="directory",
            allow_absent=True,
        )
        if observed_directory is None:
            return None
        self.journals._validate_evidence_directory(directory, attempt=attempt)
        target_name = f"verified-phase-cas-{role}.json"
        target_key = unicodedata.normalize("NFKC", target_name).casefold()
        found: CanonicalJsonRecord | None = None
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            entry_key = unicodedata.normalize("NFKC", entry.name).casefold()
            if entry_key == target_key and entry.name != target_name:
                raise CompareAndSwapConflict(
                    "verified-phase CAS observation 存在 case/NFKC alias"
                )
            record = _canonical_read(
                directory / entry.name,
                safe_root=self._safe_root,
                validator=_validate_attempt_evidence,
                label="verified-phase CAS observation checkpoint",
            )
            if record is None:
                raise CompareAndSwapConflict(
                    "verified-phase CAS observation 枚举后消失"
                )
            document = record.value
            reserved = (
                document.get("schema_version")
                == _VERIFIED_PHASE_CAS_OBSERVATION_SCHEMA
                or document.get("scope")
                == _VERIFIED_PHASE_CAS_OBSERVATION_SCOPE
            )
            if entry.name != target_name and not reserved:
                continue
            try:
                validated = _validate_verified_phase_cas_observation(
                    document
                )
            except Exception as error:
                raise CompareAndSwapConflict(
                    "reserved verified-phase CAS observation 不闭合"
                ) from error
            expected_name = (
                f"verified-phase-cas-{validated['role']}.json"
            )
            if (
                entry.name != expected_name
                or validated["attempt_id"] != attempt
            ):
                raise CompareAndSwapConflict(
                    "verified-phase CAS observation 错名或 foreign attempt"
                )
            if validated["role"] == role:
                found = CanonicalJsonRecord(
                    value=validated,
                    sha256=record.sha256,
                    raw=record.raw,
                )
        return found

    @staticmethod
    def _verified_phase_cas_documents(
        latest: Mapping[str, object],
        *,
        role: str,
    ) -> tuple[str, str, object | None, object]:
        if role == "prior":
            return (
                "active_pointer_cas",
                "active_release",
                {
                    "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                    "release": latest["pointer_cas"]["expected"],
                },
                {
                    "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                    "release": latest["pointer_cas"]["desired"],
                },
            )
        if role == "candidate":
            return (
                "local_prior_binding_cas",
                "local_prior_binding",
                latest["binding_cas"]["expected_binding"],
                latest["binding_cas"]["desired_binding"],
            )
        raise DeploymentJournalError(
            "verified-phase CAS seam 不接受 bootstrap baseline"
        )

    def consume_verified_phase_next_cas(
        self,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        authorization: object,
    ) -> CompareAndSwapResult:
        """Consume one verified authority into its journal-derived durable CAS."""

        self.assert_global_lock(lock)
        workspace._assert_live()
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        if (
            type(authorization) is not LockedVerifiedPhaseCasAuthorization
            or getattr(authorization, "_persistence", None) is not self
            or getattr(authorization, "_workspace", None) is not workspace
            or workspace._lock is not lock
            or workspace._safe_root is not self._safe_root
            or workspace._authority_token is not self._authority_token
            or workspace._acquisition_epoch is not acquisition_epoch
            or getattr(authorization, "_acquisition_epoch", None)
            is not acquisition_epoch
            or getattr(authorization, "_state", None) != "live"
        ):
            raise DeploymentLockBusy(
                "verified-phase CAS seam 只接受同 epoch exact live authorization"
            )

        try:
            latest = authorization._assert_live()  # noqa: SLF001
        except BaseException:
            authorization._mirror_release_closure_retirement()  # noqa: SLF001
            raise
        role = str(authorization._role)  # noqa: SLF001
        LockedExactTransientStartAuthorization._select_start(latest, role)
        expected_phase = (
            "prior_verified" if role == "prior" else "candidate_verified"
        )
        action, target, expected, desired = self._verified_phase_cas_documents(
            latest,
            role=role,
        )
        if (
            authorization._role != role  # noqa: SLF001
            or authorization._phase != expected_phase  # noqa: SLF001
            or authorization._next_action != action  # noqa: SLF001
            or latest["phase"] != expected_phase
            or latest["journal_sha256"]
            != authorization._journal_sha256  # noqa: SLF001
        ):
            raise DeploymentJournalError(
                "verified-phase CAS seam role/phase/action 不闭合"
            )

        if role == "prior":
            expected_value = _identity.validate_active_release(expected)
            desired_value = _identity.validate_active_release(desired)
            cas_authority = self._active
            pinned_raw = authorization._active_raw  # noqa: SLF001
            other_raw = authorization._binding_raw  # noqa: SLF001
            evidence_field = "pointer_cas_observation_sha256"
            next_phase = "pointer_cas_committed"
        else:
            expected_value = (
                None
                if expected is None
                else _identity.validate_local_prior_binding(expected)
            )
            desired_value = _identity.validate_local_prior_binding(desired)
            cas_authority = self._binding
            pinned_raw = authorization._binding_raw  # noqa: SLF001
            other_raw = authorization._active_raw  # noqa: SLF001
            evidence_field = "binding_cas_observation_sha256"
            next_phase = "binding_cas_committed"
        expected_raw = (
            None
            if expected_value is None
            else _identity.canonical_bytes(expected_value)
        )
        desired_raw = _identity.canonical_bytes(desired_value)
        observed = cas_authority.read()
        observed_raw = None if observed is None else observed.raw
        if observed_raw not in {expected_raw, desired_raw} or observed_raw != pinned_raw:
            raise CompareAndSwapConflict(
                "verified-phase CAS current record 不是 authorization pinned expected/desired"
            )

        observation_body: dict[str, object] = {
            "schema_version": _VERIFIED_PHASE_CAS_OBSERVATION_SCHEMA,
            "scope": _VERIFIED_PHASE_CAS_OBSERVATION_SCOPE,
            "attempt_id": workspace.attempt_id,
            "nonce": workspace.nonce,
            "operation": latest["operation"],
            "role": role,
            "verified_journal_sha256": latest["journal_sha256"],
            "qualification_sha256": authorization._qualification_sha256,  # noqa: SLF001
            "action": action,
            "target": target,
            "expected": expected_value,
            "desired": desired_value,
            "result": {
                "status": "desired_durable",
                "expected_sha256": (
                    None
                    if expected_raw is None
                    else hashlib.sha256(expected_raw).hexdigest()
                ),
                "desired_sha256": hashlib.sha256(desired_raw).hexdigest(),
            },
        }
        observation_body["observation_sha256"] = _identity.identity_sha256(
            observation_body
        )
        observation = _validate_verified_phase_cas_observation(
            observation_body
        )
        observation_raw = _identity.canonical_bytes(observation)
        existing_observation = self._read_verified_phase_cas_observation(
            workspace.attempt_id,
            role,
        )
        if existing_observation is not None and (
            existing_observation.raw != observation_raw
            or observed_raw == expected_raw
        ):
            raise CompareAndSwapConflict(
                "verified-phase CAS observation 在 CAS 前已存在或出现第三值"
            )

        target_parent = lock._shared_directory_guard(
            self.layout.control,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        temporary_parent = lock._shared_directory_guard(
            self.layout.temporary,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        try:
            authorization._assert_live()  # noqa: SLF001 - final pre-CAS replay.
        except BaseException:
            authorization._mirror_release_closure_retirement()  # noqa: SLF001
            raise
        desired_durable = observed_raw == desired_raw
        journal_durable = False
        result: CompareAndSwapResult
        try:
            try:
                result = cas_authority.compare_and_swap(
                    lock=lock,
                    expected=expected_value,
                    desired=desired_value,
                    target_parent=target_parent,
                    temporary_parent=temporary_parent,
                )
                desired_durable = True
            except BaseException as cas_error:
                confirmed_after_error = cas_authority.read()
                confirmed_raw = (
                    None
                    if confirmed_after_error is None
                    else confirmed_after_error.raw
                )
                if confirmed_raw == desired_raw:
                    desired_durable = True
                    result = CompareAndSwapResult(
                        "already_desired",
                        confirmed_after_error.sha256,
                    )
                elif confirmed_raw == expected_raw:
                    raise cas_error
                else:
                    desired_durable = True
                    raise CompareAndSwapConflict(
                        "verified-phase CAS outcome unknown/third value"
                    ) from cas_error

            confirmed = cas_authority.read()
            if confirmed is None or confirmed.raw != desired_raw:
                raise CompareAndSwapConflict(
                    "verified-phase CAS durable 后不是 journal desired"
                )
            if role == "prior":
                other = self.read_local_prior_binding()
            else:
                other = self.read_active_release()
            if (None if other is None else other.raw) != other_raw:
                raise CompareAndSwapConflict(
                    "verified-phase CAS 非目标 control record 漂移"
                )
            authorization._assert_post_cas_live(latest)  # noqa: SLF001

            try:
                committed_observation = self._commit_attempt_evidence(
                    lock,
                    workspace.attempt_id,
                    f"verified-phase-cas-{role}",
                    observation_raw,
                    allow_existing_exact=True,
                )
            except BaseException as evidence_error:
                replayed_observation = self._read_verified_phase_cas_observation(
                    workspace.attempt_id,
                    role,
                )
                if (
                    replayed_observation is None
                    or replayed_observation.raw != observation_raw
                ):
                    raise LocalDeploymentPersistenceError(
                        "verified-phase CAS observation commit 结果不明"
                    ) from evidence_error
                committed_observation = replayed_observation
            if committed_observation.raw != observation_raw:
                raise CompareAndSwapConflict(
                    "verified-phase CAS observation durable bytes 漂移"
                )
            authorization._assert_post_cas_live(latest)  # noqa: SLF001

            next_journal = json.loads(
                _identity.canonical_bytes(latest).decode("utf-8")
            )
            if type(next_journal) is not dict:
                raise DeploymentJournalError(
                    "verified-phase CAS next journal clone 类型漂移"
                )
            next_journal["revision"] = int(latest["revision"]) + 1
            next_journal["phase"] = next_phase
            next_journal["previous_journal_sha256"] = latest[
                "journal_sha256"
            ]
            previous_updated = _timestamp(
                latest["timestamps"]["updated_at"],
                label="verified CAS latest updated_at",
            )
            updated = datetime.now().astimezone()
            if updated < previous_updated:
                updated = previous_updated
            next_journal["timestamps"]["updated_at"] = updated.isoformat(
                timespec="seconds"
            )
            next_journal["evidence_hashes"][evidence_field] = observation[
                "observation_sha256"
            ]
            next_journal.pop("journal_sha256", None)
            next_journal["journal_sha256"] = _identity.identity_sha256(
                next_journal
            )
            validated_next = validate_deployment_journal(next_journal)
            try:
                appended = self.journals.append(next_journal, lock=lock)
            except BaseException as append_error:
                replayed = self.journals.replay(workspace.attempt_id)[-1]
                if replayed != validated_next:
                    raise DeploymentJournalError(
                        "verified-phase CAS journal append 结果不明"
                    ) from append_error
                appended = replayed
            if appended != validated_next:
                raise DeploymentJournalError(
                    "verified-phase CAS adjacent journal 未 durable 闭合"
                )
            journal_durable = True
            authorization._mark_consumed_from_b2(  # noqa: SLF001
                self,
                lock,
                workspace,
                str(latest["journal_sha256"]),
            )
            return result
        except BaseException as error:
            if journal_durable:
                object.__setattr__(authorization, "_state", "consumed")
            elif desired_durable:
                authorization._retire_owner_crash_only(  # noqa: SLF001
                    reason="verified_phase_cas_post_write_outcome_unknown"
                )
            raise error

    def commit_local_receipt(
        self,
        *,
        lock: CrashReleasedFileLock,
        receipt: object,
    ) -> CanonicalJsonRecord:
        """Create or replay one exact B1 receipt under the B2 lock.

        This is an evidence store, not an authorization seam.  Callers must
        advance the matching durable journal separately; filename, payload and
        self hash are all revalidated here before any write.
        """

        self.assert_global_lock(lock)
        try:
            validated = _identity.validate_local_receipt(receipt)
        except Exception as error:
            raise DeploymentJournalError(
                "local receipt 不满足 closed B1 contract"
            ) from error
        receipt_id = _identifier(validated["receipt_id"], label="receipt id")
        final = self.layout.receipts / f"{receipt_id}.json"
        raw = _identity.canonical_bytes(validated)
        existing = _canonical_read(
            final,
            safe_root=self._safe_root,
            validator=_identity.validate_local_receipt,
            label="local receipt",
        )
        if existing is not None:
            if existing.raw != raw:
                raise DeploymentJournalError("receipt ID 已存在第三值")
            return existing
        with _BoundDirectory(self._safe_root, self.layout.receipts) as guard:
            observed = _canonical_read(
                final,
                safe_root=self._safe_root,
                validator=_identity.validate_local_receipt,
                label="local receipt",
            )
            if observed is not None:
                if observed.raw != raw:
                    raise DeploymentJournalError(
                        "receipt create-only 前出现第三值"
                    )
                return observed
            _write_new_bound_file(
                guard,
                name=final.name,
                raw=raw,
                label="local receipt",
            )
        written = _canonical_read(
            final,
            safe_root=self._safe_root,
            validator=_identity.validate_local_receipt,
            label="local receipt",
        )
        if written is None or written.raw != raw:
            raise DeploymentJournalError("receipt durable 后重读不一致")
        return written

    def read_active_release(self) -> CanonicalJsonRecord | None:
        return self._active.read()

    def read_local_prior_binding(self) -> CanonicalJsonRecord | None:
        return self._binding.read()

    def read_local_receipts(self) -> tuple[CanonicalJsonRecord, ...]:
        """Read the complete exact B1 receipt namespace without creating it."""

        self._safe_root.preflight(
            self.layout.receipts,
            expected_kind="directory",
            allow_absent=False,
        )
        records: list[CanonicalJsonRecord] = []
        seen_names: set[str] = set()
        for entry in sorted(
            os.scandir(self.layout.receipts), key=lambda item: item.name
        ):
            folded = unicodedata.normalize("NFKC", entry.name).casefold()
            if folded in seen_names:
                raise DeploymentJournalError(
                    "receipt namespace contains a case/NFKC alias"
                )
            seen_names.add(folded)
            if not entry.name.endswith(".json"):
                raise DeploymentJournalError(
                    "receipt namespace contains a non-JSON member"
                )
            record = _canonical_read(
                self.layout.receipts / entry.name,
                safe_root=self._safe_root,
                validator=_identity.validate_local_receipt,
                label="local receipt",
            )
            if (
                record is None
                or entry.name != f"{record.value['receipt_id']}.json"
            ):
                raise DeploymentJournalError(
                    "receipt filename does not equal its exact receipt ID"
                )
            records.append(record)
        return tuple(records)

    def inspect_closed_bootstrap_baseline(
        self,
        *,
        lock: CrashReleasedFileLock,
        release_id: str,
        manifest_sha256: str,
    ) -> Mapping[str, object] | None:
        """Prove the sole R0/null non-ingress state, or report pristine absent."""

        lock.assert_held(authority_token=self._authority_token)
        active = self.read_active_release()
        binding = self.read_local_prior_binding()
        if active is None:
            if binding is not None:
                raise RetentionPlanningError(
                    "absent active pointer cannot carry a prior binding"
                )
            return None
        if binding is not None:
            raise RetentionPlanningError(
                "bootstrap baseline inspection requires absent prior binding"
            )
        release_ref = active.value["release"]
        if (
            release_ref["release_id"] != release_id
            or release_ref["manifest_sha256"] != manifest_sha256
        ):
            raise RetentionPlanningError(
                "bootstrap baseline identity differs from exact R0"
            )
        records = self.read_local_receipts()
        receipt_values = tuple(record.value for record in records)
        plan = self.plan_retention(lock=lock, receipts=receipt_values)
        if (
            plan.active.release_id != release_id
            or plan.active.manifest_sha256 != manifest_sha256
            or plan.prior is not None
            or plan.transient is not None
            or plan.cleanup_targets
            or plan.release_count != 1
        ):
            raise RetentionPlanningError(
                "bootstrap baseline retention is not exact R0/null"
            )
        histories = self.journals.histories()
        closed = [
            history[-1]
            for history in histories.values()
            if history[-1]["operation"] == "bootstrap_first_pair"
            and history[-1]["phase"] == "terminal_receipt_committed"
            and history[-1]["target_pair"]
            == {"active": release_ref, "prior": None}
        ]
        if len(closed) != 1:
            raise RetentionPlanningError(
                "bootstrap baseline lacks one exact terminal journal"
            )
        latest = closed[0]
        receipt_index = self._receipt_index(receipt_values)
        receipt = self._resolve_terminal_receipt(latest, receipt_index)
        terminal = latest["terminal_receipt"]
        bootstrap_proof = receipt["proof"]
        proof: dict[str, object] = {
            "schema_version": "qrh-closed-bootstrap-baseline-proof/v1",
            "status": "closed_non_ingress",
            "release": release_ref,
            "attempt_id": latest["attempt"],
            "terminal_journal_sha256": latest["journal_sha256"],
            "activation_receipt_id": receipt["receipt_id"],
            "activation_receipt_sha256": terminal["receipt_sha256"],
            "state_identity_sha256": receipt["state_identity"][
                "identity_sha256"
            ],
            "ingress_status": bootstrap_proof["ingress_status"],
            "legacy_c_writer_status": bootstrap_proof[
                "legacy_c_writer_status"
            ],
        }
        if (
            proof["ingress_status"] != "closed"
            or proof["legacy_c_writer_status"] != "fenced"
        ):
            raise RetentionPlanningError(
                "bootstrap baseline receipt lacks closed ingress/C fence"
            )
        proof["proof_sha256"] = _identity.identity_sha256(proof)
        return proof

    def cas_active_release(
        self,
        *,
        lock: CrashReleasedFileLock,
        expected: object | None,
        desired: object,
    ) -> CompareAndSwapResult:
        """Test-fixture-only raw CAS; production must use a typed one-shot seam."""

        if not self._test_only:
            raise DeploymentLockBusy(
                "产品 active pointer CAS 只能消费 exact one-shot authorization"
            )
        return self._active.compare_and_swap(
            lock=lock, expected=expected, desired=desired
        )

    def cas_local_prior_binding(
        self,
        *,
        lock: CrashReleasedFileLock,
        expected: object | None,
        desired: object,
    ) -> CompareAndSwapResult:
        """Test-fixture-only raw CAS; production must use a typed one-shot seam."""

        if not self._test_only:
            raise DeploymentLockBusy(
                "产品 local prior binding CAS 只能消费 exact one-shot authorization"
            )
        return self._binding.compare_and_swap(
            lock=lock, expected=expected, desired=desired
        )

    def restore_original_control_for_failure(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> Mapping[str, object]:
        """Restore the journal-sealed original pair and observe current D state.

        This is the production reverse-CAS seam.  It accepts no caller-supplied
        pointer, binding, path or state identity; all material is derived from
        the latest non-terminal v4 journal under the same B2 epoch.
        """

        self.assert_global_lock(lock)
        workspace._assert_live()
        latest = self.journals.replay(workspace.attempt_id)[-1]
        if (
            latest["attempt"] != workspace.attempt_id
            or latest["nonce"] != workspace.nonce
            or latest["operation"]
            not in {"activation", "rollback", "bootstrap_first_pair"}
            or _journal_is_closed(latest)
        ):
            raise DeploymentJournalError(
                "failure restore requires one matching non-terminal ordinary journal"
            )
        bootstrap = latest["operation"] == "bootstrap_first_pair"
        original_active = (
            None
            if bootstrap
            else {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": latest["original_pair"]["active"],
            }
        )
        target_active = {
            "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
            "release": latest["pointer_cas"]["desired"],
        }
        expected_binding = latest["binding_cas"]["expected_binding"]
        target_binding = latest["binding_cas"]["desired_binding"]
        acquisition_epoch = lock._capture_acquisition_epoch(
            authority_token=self._authority_token,
        )
        control_parent = lock._shared_directory_guard(
            self.layout.control,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )
        temporary_parent = lock._shared_directory_guard(
            self.layout.temporary,
            authority_token=self._authority_token,
            acquisition_epoch=acquisition_epoch,
        )

        current_binding = self.read_local_prior_binding()
        target_binding_raw = (
            None
            if target_binding is None
            else _identity.canonical_bytes(
                _identity.validate_local_prior_binding(target_binding)
            )
        )
        expected_binding_raw = (
            None
            if expected_binding is None
            else _identity.canonical_bytes(
                _identity.validate_local_prior_binding(expected_binding)
            )
        )
        current_binding_raw = (
            None if current_binding is None else current_binding.raw
        )
        if target_binding is not None and current_binding_raw == target_binding_raw:
            if expected_binding is None:
                self._binding.compare_and_delete(
                    lock=lock,
                    expected=target_binding,
                    target_parent=control_parent,
                )
            else:
                self._binding.compare_and_swap(
                    lock=lock,
                    expected=target_binding,
                    desired=expected_binding,
                    target_parent=control_parent,
                    temporary_parent=temporary_parent,
                )
        elif current_binding_raw != expected_binding_raw:
            raise CompareAndSwapConflict(
                "failure restore binding is not original/target"
            )

        current_active = self.read_active_release()
        target_active_raw = _identity.canonical_bytes(
            _identity.validate_active_release(target_active)
        )
        original_active_raw = (
            None
            if original_active is None
            else _identity.canonical_bytes(
                _identity.validate_active_release(original_active)
            )
        )
        current_active_raw = None if current_active is None else current_active.raw
        if current_active_raw == target_active_raw:
            if original_active is None:
                self._active.compare_and_delete(
                    lock=lock,
                    expected=target_active,
                    target_parent=control_parent,
                )
            else:
                self._active.compare_and_swap(
                    lock=lock,
                    expected=target_active,
                    desired=original_active,
                    target_parent=control_parent,
                    temporary_parent=temporary_parent,
                )
        elif current_active_raw != original_active_raw:
            raise CompareAndSwapConflict(
                "failure restore pointer is not original/target"
            )

        active_after = self.read_active_release()
        binding_after = self.read_local_prior_binding()
        if (
            (None if active_after is None else active_after.raw)
            != original_active_raw
            or (None if binding_after is None else binding_after.raw)
            != expected_binding_raw
        ):
            raise CompareAndSwapConflict(
                "failure restore did not reach the exact original control pair"
            )

        state_sources: dict[str, LockedStateSqliteSource] = {}
        try:
            for database in _STATE_SQLITE_DATABASES:
                state_sources[database] = self.lock_state_sqlite_source(
                    lock, workspace, database
                )
            state_order_sha256 = _locked_production_state_order_sha256(
                state_sources,
                persistence=self,
                workspace=workspace,
            )
        finally:
            for source in reversed(tuple(state_sources.values())):
                source.close()
        return {
            "active": None if active_after is None else active_after.value,
            "active_raw_sha256": (
                hashlib.sha256(b"absent").hexdigest()
                if active_after is None
                else active_after.sha256
            ),
            "binding": None if binding_after is None else binding_after.value,
            "binding_raw_sha256": (
                hashlib.sha256(b"absent").hexdigest()
                if binding_after is None
                else binding_after.sha256
            ),
            "state_order_sha256": state_order_sha256,
            "journal_sha256": latest["journal_sha256"],
        }

    def _scan_release(
        self,
        directory: Path,
        *,
        expected_directory_name: str | None = None,
    ) -> tuple[ReleaseInventoryEntry, Mapping[str, object]]:
        self._safe_root.preflight(
            directory, expected_kind="directory", allow_absent=False
        )
        manifest_path = directory / "release_manifest.json"
        record = _canonical_read(
            manifest_path,
            safe_root=self._safe_root,
            validator=_identity.validate_release_manifest,
            label="release manifest",
        )
        if record is None:
            raise RetentionPlanningError("release tree 缺 manifest")
        release = record.value
        release_id = str(release["release_id"])
        required_name = (
            release_id
            if expected_directory_name is None
            else expected_directory_name
        )
        if directory.name != required_name:
            raise RetentionPlanningError("release directory/release_id 不一致")
        inventory = release["inventory"]["files"]
        expected = {str(item["path"]): item for item in inventory}
        expected_directories = {
            "/".join(str(item["path"]).split("/")[:index])
            for item in inventory
            for index in range(1, len(str(item["path"]).split("/")))
        }
        actual: dict[str, Path] = {}
        actual_directories: set[str] = set()
        for current_text, directory_names, file_names in os.walk(directory):
            current = Path(current_text)
            self._safe_root.preflight(
                current, expected_kind="directory", allow_absent=False
            )
            directory_names.sort()
            file_names.sort()
            for name in directory_names:
                child_directory = current / name
                self._safe_root.preflight(
                    child_directory,
                    expected_kind="directory",
                    allow_absent=False,
                )
                actual_directories.add(
                    child_directory.relative_to(directory).as_posix()
                )
            for name in file_names:
                path = current / name
                metadata = self._safe_root.preflight(
                    path, expected_kind="file", allow_absent=False
                )
                if metadata is None or getattr(metadata, "st_nlink", 1) != 1:
                    raise RetentionPlanningError("release closure 含 hardlink/漂移文件")
                relative = path.relative_to(directory).as_posix()
                if relative == "release_manifest.json":
                    continue
                folded = relative.casefold()
                if any(existing.casefold() == folded for existing in actual):
                    raise RetentionPlanningError("release closure 含 case-fold 碰撞")
                actual[relative] = path
        if set(actual) != set(expected):
            raise RetentionPlanningError("release closure 文件集合不闭合")
        if actual_directories != expected_directories:
            raise RetentionPlanningError("release closure 目录集合不闭合")
        for relative, path in actual.items():
            metadata = os.stat(path, follow_symlinks=False)
            expected_record = expected[relative]
            if (
                metadata.st_size != expected_record["bytes"]
                or _stream_sha256(path) != expected_record["sha256"]
            ):
                raise RetentionPlanningError("release closure size/hash 漂移")
        closure_sha256 = str(release["resources"]["inventory_sha256"])
        return (
            ReleaseInventoryEntry(
                release_id=release_id,
                canonical_path=str(directory),
                manifest_sha256=record.sha256,
                closure_sha256=closure_sha256,
            ),
            release,
        )

    def inspect_exact_incoming_candidate(
        self,
        *,
        lock: CrashReleasedFileLock,
        release_id: str,
        expected_manifest_sha256: str,
    ) -> Mapping[str, object]:
        """Pin one complete v2 candidate while it is still under ``incoming``."""

        self.assert_global_lock(lock)
        candidate_id = _identifier(release_id, label="candidate release id")
        expected_hash = _sha256(
            expected_manifest_sha256,
            label="candidate release manifest sha256",
        )
        partial_name = f"{candidate_id}.partial"
        partial = self.layout.incoming / partial_name
        entry, manifest = self._scan_release(
            partial,
            expected_directory_name=partial_name,
        )
        if (
            entry.release_id != candidate_id
            or entry.manifest_sha256 != expected_hash
        ):
            raise RetentionPlanningError(
                "incoming candidate release ID/manifest hash differs"
            )
        if (self.layout.releases / candidate_id).exists():
            raise RetentionPlanningError(
                "incoming candidate collides with a finalized release"
            )
        return manifest

    def capture_candidate_validation_invariants(
        self,
        *,
        lock: CrashReleasedFileLock,
        release_id: str,
        expected_manifest_sha256: str,
    ) -> Mapping[str, object]:
        """Freeze all authorities that candidate-only is forbidden to mutate."""

        self.assert_global_lock(lock)
        candidate = self.inspect_exact_incoming_candidate(
            lock=lock,
            release_id=release_id,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        if self.journals.active_revisions():
            raise DeploymentJournalError(
                "candidate-only cannot overlap an active deployment journal"
            )
        active = self.read_active_release()
        binding = self.read_local_prior_binding()
        receipts = [
            {
                "receipt_id": record.value["receipt_id"],
                "receipt_sha256": record.value["receipt_sha256"],
                "raw_sha256": record.sha256,
            }
            for record in self.read_local_receipts()
        ]
        histories = {
            attempt: list(history)
            for attempt, history in sorted(self.journals.histories().items())
        }
        inventory = [
            {
                "release_id": entry.release_id,
                "manifest_sha256": entry.manifest_sha256,
                "closure_sha256": entry.closure_sha256,
            }
            for entry in self.release_inventory()
        ]
        return {
            "candidate_manifest_sha256": _identity.identity_sha256(candidate),
            "active_pointer_raw_sha256": (
                hashlib.sha256(b"absent").hexdigest()
                if active is None
                else active.sha256
            ),
            "local_prior_binding_raw_sha256": (
                hashlib.sha256(b"absent").hexdigest()
                if binding is None
                else binding.sha256
            ),
            "receipt_inventory_sha256": _identity.identity_sha256(receipts),
            "journal_history_sha256": _identity.identity_sha256(histories),
            "finalized_release_inventory_sha256": _identity.identity_sha256(
                inventory
            ),
        }

    def commit_candidate_validation_event(
        self,
        *,
        lock: CrashReleasedFileLock,
        release_id: str,
        expected_manifest_sha256: str,
        publish_candidate_sha256: str,
        probe_evidence: Mapping[str, object],
        invariants_before: Mapping[str, object],
    ) -> str:
        """Commit one evidence-only v2 incoming-candidate validation event."""

        self.assert_global_lock(lock)
        release = self.inspect_exact_incoming_candidate(
            lock=lock,
            release_id=release_id,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        expected_probe_fields = {
            "schema_version",
            "release_id",
            "manifest_sha256",
            "snapshot_id",
            "transport",
            "writer_authority",
            "health",
            "browser",
            "api",
            "resource",
            "state_isolated",
            "active_unchanged",
            "cleaned",
        }
        snapshot_id = release["content"]["snapshot_id"]
        if (
            not isinstance(probe_evidence, dict)
            or set(probe_evidence) != expected_probe_fields
            or probe_evidence.get("schema_version")
            != "qrh-candidate-probe-evidence/v1"
            or probe_evidence.get("release_id") != release_id
            or probe_evidence.get("manifest_sha256")
            != expected_manifest_sha256
            or probe_evidence.get("snapshot_id") != snapshot_id
            or probe_evidence.get("transport") != "loopback_isolated"
            or probe_evidence.get("writer_authority")
            != "candidate-checkpoint-isolated"
            or any(
                probe_evidence.get(field) is not True
                for field in (
                    "health",
                    "browser",
                    "api",
                    "resource",
                    "state_isolated",
                    "active_unchanged",
                    "cleaned",
                )
            )
        ):
            raise RetentionPlanningError(
                "v2 candidate-only probe evidence is not closed/passing"
            )
        invariants_after = self.capture_candidate_validation_invariants(
            lock=lock,
            release_id=release_id,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        if invariants_after != invariants_before:
            raise CompareAndSwapConflict(
                "candidate-only changed control/journal/receipt/release authority"
            )
        publish_hash = _sha256(
            publish_candidate_sha256,
            label="candidate-only publish candidate sha256",
        )
        event_identity = _identity.identity_sha256(
            {
                "release_id": release_id,
                "manifest_sha256": expected_manifest_sha256,
                "publish_candidate_sha256": publish_hash,
                "probe_evidence": probe_evidence,
                "invariants": invariants_before,
            }
        )
        event_id = f"candidate-validation-completed-{event_identity}"
        event: dict[str, object] = {
            "schema_version": "qrh-candidate-validation-event/v2",
            "event_id": event_id,
            "recorded_at": datetime.now().astimezone().isoformat(),
            "authority": "evidence_only",
            "kind": "candidate_validation_completed",
            "candidate": {
                "release_id": release_id,
                "release_path": str(
                    _identity.PRODUCTION_INCOMING_ROOT / f"{release_id}.partial"
                ),
                "manifest_sha256": expected_manifest_sha256,
                "snapshot_id": snapshot_id,
            },
            "publish_candidate_sha256": publish_hash,
            "probe_evidence": dict(probe_evidence),
            "invariants": dict(invariants_before),
        }
        event["event_sha256"] = _identity.identity_sha256(event)
        raw = _identity.canonical_bytes(event)
        target = self.layout.events / f"{event_id}.json"
        existing = _canonical_read(
            target,
            safe_root=self._safe_root,
            validator=_validate_attempt_evidence,
            label="candidate validation event",
        )
        if existing is not None:
            existing_value = dict(existing.value)
            existing_value.pop("recorded_at", None)
            replay_value = dict(event)
            replay_value.pop("recorded_at", None)
            # event_sha256 includes recorded_at; semantic fields and deterministic
            # event_id are the replay authority, while first-write time remains audit.
            existing_value.pop("event_sha256", None)
            replay_value.pop("event_sha256", None)
            if existing_value != replay_value:
                raise CompareAndSwapConflict(
                    "candidate validation event ID collides with another payload"
                )
            return event_id
        with _BoundDirectory(self._safe_root, self.layout.events) as parent:
            _write_new_bound_file(
                parent,
                name=target.name,
                raw=raw,
                label="candidate validation event",
            )
        confirmed = _canonical_read(
            target,
            safe_root=self._safe_root,
            validator=_validate_attempt_evidence,
            label="candidate validation event",
        )
        if confirmed is None or confirmed.raw != raw:
            raise CompareAndSwapConflict(
                "candidate validation event create-through 漂移"
            )
        return event_id

    def finalize_exact_incoming_candidate(
        self,
        *,
        lock: CrashReleasedFileLock,
        release_id: str,
        expected_manifest_sha256: str,
    ) -> Mapping[str, object]:
        """Atomically move the journal-authorized exact candidate into releases."""

        self.assert_global_lock(lock)
        candidate_id = _identifier(release_id, label="candidate release id")
        expected_hash = _sha256(
            expected_manifest_sha256,
            label="candidate release manifest sha256",
        )
        partial_name = f"{candidate_id}.partial"
        partial = self.layout.incoming / partial_name
        final = self.layout.releases / candidate_id
        active_journals = self.journals.active_revisions()
        if len(active_journals) != 1:
            raise DeploymentJournalError(
                "candidate finalize requires one exact active journal"
            )
        journal = active_journals[0]
        candidate_ref = journal["candidate"]
        if (
            journal["phase"] != "intent_durable"
            or journal["operation"]
            not in {"activation", "rollback", "bootstrap_first_pair"}
            or candidate_ref["release_id"] != candidate_id
            or candidate_ref["manifest_sha256"] != expected_hash
        ):
            raise DeploymentJournalError(
                "candidate finalize is not authorized by the durable intent"
            )
        if final.exists():
            if partial.exists():
                raise RetentionPlanningError(
                    "candidate exists as both incoming and finalized"
                )
            entry, manifest = self._scan_release(final)
            if entry.manifest_sha256 != expected_hash:
                raise RetentionPlanningError(
                    "finalized candidate manifest hash differs"
                )
            return manifest

        entry_before, manifest_before = self._scan_release(
            partial,
            expected_directory_name=partial_name,
        )
        if (
            entry_before.release_id != candidate_id
            or entry_before.manifest_sha256 != expected_hash
        ):
            raise RetentionPlanningError(
                "incoming candidate release ID/manifest hash differs"
            )
        try:
            with _BoundDirectory(
                self._safe_root, self.layout.incoming
            ) as source_guard, _BoundDirectory(
                self._safe_root, self.layout.releases
            ) as destination_guard:
                if final.exists():
                    raise RetentionPlanningError(
                        "candidate destination appeared before finalize"
                    )
                destination_guard.replace_from(
                    source_guard,
                    source_name=partial_name,
                    destination_name=candidate_id,
                )
                source_guard.flush()
                destination_guard.flush()
        except BaseException as error:
            if not final.exists() or partial.exists():
                raise
            try:
                entry_after_error, manifest_after_error = self._scan_release(final)
            except BaseException as proof_error:
                raise LocalDeploymentPersistenceError(
                    "candidate finalize outcome is unknown"
                ) from proof_error
            if (
                entry_after_error.manifest_sha256 != expected_hash
                or manifest_after_error != manifest_before
            ):
                raise LocalDeploymentPersistenceError(
                    "candidate finalize produced a third value"
                ) from error
            return manifest_after_error

        if partial.exists():
            raise LocalDeploymentPersistenceError(
                "candidate incoming path remains after finalize"
            )
        entry_after, manifest_after = self._scan_release(final)
        if (
            entry_after.manifest_sha256 != expected_hash
            or entry_after.closure_sha256 != entry_before.closure_sha256
            or manifest_after != manifest_before
        ):
            raise LocalDeploymentPersistenceError(
                "candidate closure drifted across atomic finalize"
            )
        return manifest_after

    def release_inventory(self) -> tuple[ReleaseInventoryEntry, ...]:
        self._safe_root.preflight(
            self.layout.releases,
            expected_kind="directory",
            allow_absent=False,
        )
        entries: list[ReleaseInventoryEntry] = []
        seen: set[str] = set()
        try:
            children = sorted(os.scandir(self.layout.releases), key=lambda item: item.name)
        except OSError as error:
            raise RetentionPlanningError("无法枚举 releases") from error
        for child in children:
            folded = child.name.casefold()
            if folded in seen:
                raise RetentionPlanningError("release directory case-fold 碰撞")
            seen.add(folded)
            _identifier(child.name, label="release directory")
            entry, _ = self._scan_release(self.layout.releases / child.name)
            entries.append(entry)
        return tuple(entries)

    @staticmethod
    def _entry_for_ref(
        reference: Mapping[str, object],
        inventory: Sequence[ReleaseInventoryEntry],
        *,
        label: str,
    ) -> ReleaseInventoryEntry:
        matches = [
            item
            for item in inventory
            if item.manifest_sha256 == reference["manifest_sha256"]
        ]
        if len(matches) != 1 or matches[0].release_id != reference["release_id"]:
            raise RetentionPlanningError(f"{label} 未解析到 exact release closure")
        return matches[0]

    def _manifest_for_entry(
        self, entry: ReleaseInventoryEntry
    ) -> Mapping[str, object]:
        record = _canonical_read(
            Path(entry.canonical_path) / "release_manifest.json",
            safe_root=self._safe_root,
            validator=_identity.validate_release_manifest,
            label="retained release manifest",
        )
        if record is None or record.sha256 != entry.manifest_sha256:
            raise RetentionPlanningError("retained manifest 在 inventory 后漂移")
        return record.value

    @staticmethod
    def _assert_release_supports_state(
        release: Mapping[str, object],
        state: Mapping[str, object],
        *,
        label: str,
    ) -> None:
        compatibility = release["state"]["compatibility"]
        versions = state["schema_versions"]
        if set(compatibility) != {*versions, "rollback_policy"}:
            raise RetentionPlanningError(f"{label} state database set 漂移")
        for name, version in versions.items():
            if (
                version not in compatibility[name]["read"]
                or version not in compatibility[name]["write"]
            ):
                raise RetentionPlanningError(
                    f"{label} 不支持当前 D state read/write identity"
                )

    @staticmethod
    def _receipt_index(receipts: Sequence[object]) -> Mapping[tuple[str, str], Mapping[str, object]]:
        if isinstance(receipts, (str, bytes)) or not isinstance(receipts, Sequence):
            raise RetentionPlanningError("receipts 必须是 sequence")
        result: dict[tuple[str, str], Mapping[str, object]] = {}
        ids: set[str] = set()
        terminal_attempts: set[str] = set()
        cleanup_attempts: set[str] = set()
        terminal_by_attempt: dict[str, Mapping[str, object]] = {}
        cleanup_by_attempt: dict[str, Mapping[str, object]] = {}
        for raw in receipts:
            try:
                receipt = _identity.validate_local_receipt(raw)
            except Exception as error:
                raise RetentionPlanningError("历史 receipt 不满足 B1 closed schema") from error
            receipt_id = str(receipt["receipt_id"])
            folded = receipt_id.casefold()
            if folded in ids:
                raise RetentionPlanningError("历史 receipt_id 重复")
            ids.add(folded)
            key = (receipt_id, str(receipt["receipt_sha256"]))
            result[key] = receipt
            attempt = str(receipt["attempt_id"]).casefold()
            if receipt["schema_version"] == _identity.CLEANUP_RECEIPT_SCHEMA:
                if attempt in cleanup_attempts:
                    raise RetentionPlanningError("同 attempt 多个 cleanup receipt")
                cleanup_attempts.add(attempt)
                cleanup_by_attempt[attempt] = receipt
            else:
                if attempt in terminal_attempts:
                    raise RetentionPlanningError("同 attempt 多个 terminal receipt")
                terminal_attempts.add(attempt)
                terminal_by_attempt[attempt] = receipt
        for attempt, cleanup in cleanup_by_attempt.items():
            terminal = terminal_by_attempt.get(attempt)
            if (
                terminal is None
                or terminal["schema_version"]
                not in {
                    _identity.ACTIVATION_RECEIPT_SCHEMA,
                    _identity.ROLLBACK_RECEIPT_SCHEMA,
                }
                or terminal.get("operation") == "bootstrap_first_pair"
                or cleanup["retained_pair"] != terminal["pair"]
            ):
                raise RetentionPlanningError(
                    "cleanup receipt 必须接同 attempt 非 bootstrap 成功 terminal/pair"
                )
        return result

    @staticmethod
    def _resolve_terminal_receipt(
        journal: Mapping[str, object],
        receipt_index: Mapping[tuple[str, str], Mapping[str, object]],
    ) -> Mapping[str, object]:
        terminal = journal["terminal_receipt"]
        if terminal is None:
            raise RetentionPlanningError("cleanup/terminal 缺 typed terminal receipt")
        receipt = receipt_index.get(
            (str(terminal["receipt_id"]), str(terminal["receipt_sha256"]))
        )
        if receipt is None or receipt["attempt_id"] != journal["attempt"]:
            raise RetentionPlanningError("terminal receipt ID/hash/attempt 未精确解析")
        expected_schema = {
            "activation": _identity.ACTIVATION_RECEIPT_SCHEMA,
            "rollback": _identity.ROLLBACK_RECEIPT_SCHEMA,
            "failure": _identity.FAILURE_RECEIPT_SCHEMA,
        }[str(terminal["kind"])]
        if receipt["schema_version"] != expected_schema:
            raise RetentionPlanningError("terminal receipt kind/schema 不一致")
        if terminal["kind"] == "failure":
            expected_failure_operation = _FAILURE_RECEIPT_OPERATION[
                str(journal["operation"])
            ]
            if (
                terminal.get("operation") != expected_failure_operation
                or receipt.get("operation") != expected_failure_operation
                or receipt.get("failed_phase") != terminal.get("failed_phase")
            ):
                raise RetentionPlanningError(
                    "failure receipt 未绑定 journal operation/failed_phase"
                )
            expected_original = (
                {"kind": "bootstrap_no_d_pair", "pair": None}
                if journal["operation"] == "bootstrap_first_pair"
                else {"kind": "release_pair", "pair": journal["original_pair"]}
            )
            if (
                receipt["original_pair"] != expected_original
                or receipt["candidate"] != journal["candidate"]
                or receipt.get("original_state_identity", {}).get("identity_sha256")
                != journal["state_plan"]["state_identity_sha256"]
            ):
                raise RetentionPlanningError(
                    "failure receipt 未绑定 original/candidate/original D state"
                )
            restoration = receipt.get("restoration_evidence")
            if not isinstance(restoration, dict):
                raise RetentionPlanningError("failure receipt 缺 sealed restoration evidence")
            expected_observations = {
                "failure_original_pointer_observation_sha256": "original_active_pointer_observation",
                "failure_original_binding_observation_sha256": "original_local_prior_binding_observation",
                "failure_original_service_observation_sha256": "original_active_service_live_identity_observation",
                "failure_original_writer_fence_observation_sha256": "original_active_writer_fence_observation",
                "failure_state_identity_observation_sha256": "current_d_state_identity_observation",
            }
            if any(
                not isinstance(restoration.get(receipt_field), dict)
                or journal["evidence_hashes"][journal_field]
                != restoration[receipt_field].get("observation_sha256")
                for journal_field, receipt_field in expected_observations.items()
            ):
                raise RetentionPlanningError(
                    "failure journal 未精确绑定 pointer/binding/service/writer/state observations"
                )
        else:
            if receipt["pair"] != journal["target_pair"]:
                raise RetentionPlanningError("success receipt 未绑定 target pair")
            expected_operation = {
                "activation": "activate_successor",
                "rollback": "rollback_to_prior",
                "bootstrap_first_pair": "bootstrap_first_pair",
            }[str(journal["operation"])]
            if receipt["operation"] != expected_operation:
                raise RetentionPlanningError("success receipt operation 不一致")
            if (
                journal["operation"] != "bootstrap_first_pair"
                and receipt["result"].get("controller_verification_sha256")
                != journal["evidence_hashes"]["controller_verification_sha256"]
            ):
                raise RetentionPlanningError(
                    "success receipt 未绑定 journal controller verification"
                )
            if journal["operation"] == "bootstrap_first_pair" and (
                receipt["original"]
                != {
                    "active_pointer_status": "absent",
                    "local_prior_binding_status": "absent",
                }
                or receipt["state_identity"]["identity_sha256"]
                != journal["state_plan"]["state_identity_sha256"]
                or receipt["proof"]["r0_live"] != journal["candidate"]
            ):
                raise RetentionPlanningError("bootstrap receipt 未闭合 absent/R0/D-state")
        return receipt

    def _physical_cleanup_path(self, target: Mapping[str, object]) -> Path:
        kind = str(target["kind"])
        logical = PureWindowsPath(str(target["path"]))
        logical_root = (
            _identity.PRODUCTION_OBJECT_ROOT
            if kind == "unreferenced_object"
            else _identity.PRODUCTION_INCOMING_ROOT
        )
        relative = logical.relative_to(logical_root)
        physical_root = self.layout.root / ("objects" if kind == "unreferenced_object" else "incoming")
        return physical_root.joinpath(*relative.parts)

    def _plan_cleanup_target(
        self,
        target: Mapping[str, object],
        inventory: Sequence[ReleaseInventoryEntry],
    ) -> CleanupTargetPlan | None:
        kind = str(target["kind"])
        if kind == "release_closure":
            reference = target["release"]
            matches = [
                item for item in inventory
                if item.release_id == reference["release_id"]
                and item.manifest_sha256 == reference["manifest_sha256"]
            ]
            if not matches:
                return None
            entry = matches[0]
            if entry.closure_sha256 != target["closure_sha256"]:
                raise RetentionPlanningError("release cleanup closure 漂移")
            return ReleaseCleanupTargetPlan(
                kind=kind,
                canonical_path=entry.canonical_path,
                release_id=entry.release_id,
                manifest_sha256=entry.manifest_sha256,
                closure_sha256=entry.closure_sha256,
            )
        path = self._physical_cleanup_path(target)
        metadata = self._safe_root.preflight(path, allow_absent=True)
        if metadata is None:
            return None
        if not stat.S_ISREG(metadata.st_mode) or getattr(metadata, "st_nlink", 1) != 1:
            raise RetentionPlanningError("incoming/object cleanup target 必须是普通独占文件")
        payload_hash = _stream_sha256(path)
        hash_field = "object_sha256" if kind == "unreferenced_object" else "payload_sha256"
        if payload_hash != target[hash_field]:
            raise RetentionPlanningError("cleanup payload/object hash 漂移")
        closure = _identity.identity_sha256(
            {
                "kind": kind,
                "path": str(target["path"]),
                hash_field: payload_hash,
                "bytes": metadata.st_size,
            }
        )
        if closure != target["closure_sha256"]:
            raise RetentionPlanningError("cleanup target closure seal 漂移")
        if kind == "incoming":
            return IncomingCleanupTargetPlan(kind, str(path), payload_hash, closure)
        if kind == "partial":
            return PartialCleanupTargetPlan(kind, str(path), payload_hash, closure)
        return UnreferencedObjectCleanupTargetPlan(kind, str(path), payload_hash, closure)

    def _delete_exact_release_cleanup_target(
        self,
        target: ReleaseCleanupTargetPlan,
    ) -> None:
        release_root = Path(target.canonical_path)
        expected_root = self.layout.releases / target.release_id
        if release_root != expected_root:
            raise RetentionPlanningError(
                "release cleanup target is outside the exact releases namespace"
            )
        entry, manifest = self._scan_release(release_root)
        if (
            entry.release_id != target.release_id
            or entry.manifest_sha256 != target.manifest_sha256
            or entry.closure_sha256 != target.closure_sha256
        ):
            raise RetentionPlanningError(
                "release cleanup target drifted after retention planning"
            )

        members = [
            str(item["path"])
            for item in manifest["inventory"]["files"]
        ]
        for relative in members:
            parts = tuple(relative.split("/"))
            path = release_root.joinpath(*parts)
            expected_member = next(
                item
                for item in manifest["inventory"]["files"]
                if item["path"] == relative
            )
            observed = self._safe_root.preflight(
                path, expected_kind="file", allow_absent=False
            )
            if (
                observed is None
                or getattr(observed, "st_nlink", 1) != 1
                or observed.st_size != expected_member["bytes"]
                or _stream_sha256(path) != expected_member["sha256"]
            ):
                raise RetentionPlanningError(
                    "release cleanup member drifted before unlink"
                )
            with _BoundDirectory(self._safe_root, path.parent) as parent:
                confirmed = self._safe_root.preflight(
                    path, expected_kind="file", allow_absent=False
                )
                if (
                    confirmed is None
                    or not _same_file_identity(observed, confirmed)
                    or getattr(confirmed, "st_nlink", 1) != 1
                ):
                    raise RetentionPlanningError(
                        "release cleanup member identity drifted before unlink"
                    )
                parent.unlink(path.name)
                parent.flush()
            if self._safe_root.preflight(
                path, expected_kind=None, allow_absent=True
            ) is not None:
                raise RetentionPlanningError(
                    "release cleanup member remains after unlink"
                )

        manifest_path = release_root / "release_manifest.json"
        manifest_record = _canonical_read(
            manifest_path,
            safe_root=self._safe_root,
            validator=_identity.validate_release_manifest,
            label="release cleanup manifest",
        )
        if (
            manifest_record is None
            or manifest_record.sha256 != target.manifest_sha256
        ):
            raise RetentionPlanningError(
                "release cleanup manifest drifted before unlink"
            )
        with _BoundDirectory(self._safe_root, release_root) as release_guard:
            release_guard.unlink("release_manifest.json")
            release_guard.flush()

        directories = {
            "/".join(relative.split("/")[:depth])
            for relative in members
            for depth in range(1, len(relative.split("/")))
        }
        for relative in sorted(
            directories,
            key=lambda item: (-len(item.split("/")), item),
        ):
            directory = release_root.joinpath(*relative.split("/"))
            with os.scandir(directory) as entries:
                if any(entries):
                    raise RetentionPlanningError(
                        "release cleanup directory contains an unknown member"
                    )
            with _BoundDirectory(self._safe_root, directory.parent) as parent:
                self._safe_root.preflight(
                    directory, expected_kind="directory", allow_absent=False
                )
                parent.rmdir(directory.name)
                parent.flush()
        with os.scandir(release_root) as entries:
            if any(entries):
                raise RetentionPlanningError(
                    "release cleanup root contains an unknown member"
                )
        with _BoundDirectory(self._safe_root, self.layout.releases) as parent:
            self._safe_root.preflight(
                release_root, expected_kind="directory", allow_absent=False
            )
            parent.rmdir(target.release_id)
            parent.flush()
        if self._safe_root.preflight(
            release_root, expected_kind=None, allow_absent=True
        ) is not None:
            raise RetentionPlanningError(
                "release cleanup root remains after removal"
            )

    def cleanup_failed_candidate(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt_id: str,
    ) -> bool:
        """Quarantine then idempotently erase one failure-terminal candidate.

        The releases-namespace removal is one atomic rename.  A controller
        crash during physical erasure therefore cannot leave a partial third
        release that blocks the next ordinary steady boot; replay resumes the
        fixed quarantine using the still-canonical manifest, or an empty
        directory skeleton after that manifest was removed last.
        """

        self.assert_global_lock(lock)
        attempt = _safe_identifier(attempt_id, label="failure cleanup attempt")
        latest = self.journals.replay(attempt)[-1]
        if latest["phase"] != _FAILURE_PHASE:
            raise DeploymentJournalError(
                "failure candidate cleanup requires a failure terminal"
            )
        receipts = tuple(record.value for record in self.read_local_receipts())
        receipt_index = self._receipt_index(receipts)
        receipt = self._resolve_terminal_receipt(latest, receipt_index)
        if receipt["schema_version"] != _identity.FAILURE_RECEIPT_SCHEMA:
            raise RetentionPlanningError(
                "failure candidate cleanup lacks exact failure receipt"
            )
        original = latest["original_pair"]
        candidate = latest["candidate"]
        active = self.read_active_release()
        binding = self.read_local_prior_binding()
        expected_active = (
            None
            if original is None
            else {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": original["active"],
            }
        )
        expected_binding = latest["binding_cas"]["expected_binding"]
        if (
            (None if active is None else active.value) != expected_active
            or (None if binding is None else binding.value) != expected_binding
        ):
            raise RetentionPlanningError(
                "failure candidate cleanup requires restored original controls"
            )

        candidate_id = str(candidate["release_id"])
        final = self.layout.releases / candidate_id
        quarantine_parent = self.layout.temporary / "f"
        quarantine_name = "q"
        quarantine_digest = hashlib.sha256(
            _identity.canonical_bytes(
                {
                    "attempt": attempt,
                    "candidate": candidate,
                }
            )
        ).hexdigest()
        quarantine = quarantine_parent / quarantine_name
        legacy_parent = self.layout.temporary / "failure-release-cleanup"
        legacy_name = f"failure-{quarantine_digest[:48]}.partial"
        legacy_quarantine = legacy_parent / legacy_name

        def remove_empty_quarantine_parents() -> None:
            for parent_path in (quarantine_parent, legacy_parent):
                if self._safe_root.preflight(
                    parent_path,
                    expected_kind="directory",
                    allow_absent=True,
                ) is None:
                    continue
                with os.scandir(parent_path) as entries:
                    if any(entries):
                        continue
                with _BoundDirectory(
                    self._safe_root, self.layout.temporary
                ) as temporary_guard:
                    temporary_guard.rmdir(parent_path.name)
                    temporary_guard.flush()

        final_present = self._safe_root.preflight(
            final, expected_kind="directory", allow_absent=True
        )
        quarantine_present = self._safe_root.preflight(
            quarantine, expected_kind="directory", allow_absent=True
        )
        legacy_present = self._safe_root.preflight(
            legacy_quarantine,
            expected_kind="directory",
            allow_absent=True,
        )
        if sum(
            item is not None
            for item in (final_present, quarantine_present, legacy_present)
        ) > 1:
            raise RetentionPlanningError(
                "failure candidate exists in multiple cleanup namespaces"
            )
        if legacy_present is not None:
            with _BoundDirectory(
                self._safe_root, self.layout.temporary
            ) as temporary_guard:
                if self._safe_root.preflight(
                    quarantine_parent,
                    expected_kind="directory",
                    allow_absent=True,
                ) is None:
                    temporary_guard.mkdir(quarantine_parent.name, 0o700)
                    temporary_guard.flush()
            with _BoundDirectory(
                self._safe_root, legacy_parent
            ) as source_guard, _BoundDirectory(
                self._safe_root, quarantine_parent
            ) as destination_guard:
                destination_guard.replace_from(
                    source_guard,
                    source_name=legacy_name,
                    destination_name=quarantine_name,
                )
                source_guard.flush()
                destination_guard.flush()
            quarantine_present = self._safe_root.preflight(
                quarantine, expected_kind="directory", allow_absent=False
            )
        if final_present is not None:
            entry, _manifest = self._scan_release(final)
            if (
                entry.release_id != candidate_id
                or entry.manifest_sha256 != candidate["manifest_sha256"]
            ):
                raise RetentionPlanningError(
                    "failure candidate release closure differs from journal"
                )
            with _BoundDirectory(
                self._safe_root, self.layout.temporary
            ) as temporary_guard:
                if self._safe_root.preflight(
                    quarantine_parent,
                    expected_kind="directory",
                    allow_absent=True,
                ) is None:
                    temporary_guard.mkdir(quarantine_parent.name, 0o700)
                    temporary_guard.flush()
            with _BoundDirectory(
                self._safe_root, self.layout.releases
            ) as source_guard, _BoundDirectory(
                self._safe_root, quarantine_parent
            ) as destination_guard:
                destination_guard.replace_from(
                    source_guard,
                    source_name=candidate_id,
                    destination_name=quarantine_name,
                )
                source_guard.flush()
                destination_guard.flush()
            quarantine_present = self._safe_root.preflight(
                quarantine, expected_kind="directory", allow_absent=False
            )
        if quarantine_present is None:
            remove_empty_quarantine_parents()
            return False

        manifest_path = quarantine / "release_manifest.json"
        manifest_record = _canonical_read(
            manifest_path,
            safe_root=self._safe_root,
            validator=_identity.validate_release_manifest,
            label="failure cleanup quarantined manifest",
        )
        if manifest_record is not None:
            manifest = manifest_record.value
            if (
                manifest["release_id"] != candidate_id
                or manifest_record.sha256 != candidate["manifest_sha256"]
            ):
                raise RetentionPlanningError(
                    "failure cleanup quarantine manifest differs"
                )
            for item in manifest["inventory"]["files"]:
                path = quarantine.joinpath(*str(item["path"]).split("/"))
                observed = self._safe_root.preflight(
                    path, expected_kind="file", allow_absent=True
                )
                if observed is None:
                    continue
                if (
                    getattr(observed, "st_nlink", 1) != 1
                    or observed.st_size != item["bytes"]
                    or _stream_sha256(path) != item["sha256"]
                ):
                    raise RetentionPlanningError(
                        "failure cleanup quarantined member drifted"
                    )
                with _BoundDirectory(self._safe_root, path.parent) as parent:
                    parent.unlink(path.name)
                    parent.flush()
            confirmed_manifest = _canonical_read(
                manifest_path,
                safe_root=self._safe_root,
                validator=_identity.validate_release_manifest,
                label="failure cleanup quarantined manifest",
            )
            if (
                confirmed_manifest is None
                or confirmed_manifest.raw != manifest_record.raw
            ):
                raise RetentionPlanningError(
                    "failure cleanup quarantine manifest drifted"
                )
            with _BoundDirectory(self._safe_root, quarantine) as root_guard:
                root_guard.unlink("release_manifest.json")
                root_guard.flush()

        directories: list[Path] = []
        for current_text, directory_names, file_names in os.walk(quarantine):
            current = Path(current_text)
            if file_names:
                raise RetentionPlanningError(
                    "failure cleanup quarantine contains unknown files"
                )
            directories.extend(current / name for name in directory_names)
        for directory in sorted(
            directories,
            key=lambda path: (-len(path.relative_to(quarantine).parts), str(path)),
        ):
            with os.scandir(directory) as entries:
                if any(entries):
                    raise RetentionPlanningError(
                        "failure cleanup quarantine directory is not empty"
                    )
            with _BoundDirectory(self._safe_root, directory.parent) as parent:
                parent.rmdir(directory.name)
                parent.flush()
        with os.scandir(quarantine) as entries:
            if any(entries):
                raise RetentionPlanningError(
                    "failure cleanup quarantine root is not empty"
                )
        with _BoundDirectory(self._safe_root, quarantine_parent) as parent:
            parent.rmdir(quarantine_name)
            parent.flush()
        remove_empty_quarantine_parents()
        return True

    def execute_retention_cleanup(
        self,
        *,
        lock: CrashReleasedFileLock,
        receipts: Sequence[object],
    ) -> tuple[Mapping[str, object], ...]:
        """Consume the current cleanup-planned journal into exact removals."""

        self.assert_global_lock(lock)
        active = self.journals.active_revisions()
        if len(active) != 1 or active[0]["phase"] != "cleanup_planned":
            raise DeploymentJournalError(
                "retention cleanup requires one cleanup-planned journal"
            )
        journal = active[0]
        plan = self.plan_retention(lock=lock, receipts=receipts)
        raw_targets = tuple(journal["cleanup_targets"])
        planned_by_identity: dict[tuple[str, str], ReleaseCleanupTargetPlan] = {}
        for target in plan.cleanup_targets:
            if type(target) is not ReleaseCleanupTargetPlan:
                raise RetentionPlanningError(
                    "this activation cleanup gate accepts only release closures"
                )
            planned_by_identity[(target.release_id, target.manifest_sha256)] = target
        for raw in raw_targets:
            if raw["kind"] != "release_closure":
                raise RetentionPlanningError(
                    "this activation cleanup gate accepts only release closures"
                )
            reference = raw["release"]
            key = (
                str(reference["release_id"]),
                str(reference["manifest_sha256"]),
            )
            target = planned_by_identity.pop(key, None)
            if target is None:
                target_path = self.layout.releases / key[0]
                if self._safe_root.preflight(
                    target_path,
                    expected_kind=None,
                    allow_absent=True,
                ) is not None:
                    raise RetentionPlanningError(
                        "journal cleanup target is neither planned nor already absent"
                    )
                continue
            matching = [
                candidate
                for candidate in raw_targets
                if candidate["kind"] == "release_closure"
                and candidate["release"]["release_id"] == target.release_id
                and candidate["release"]["manifest_sha256"]
                == target.manifest_sha256
                and candidate["closure_sha256"] == target.closure_sha256
            ]
            if len(matching) != 1:
                raise RetentionPlanningError(
                    "typed cleanup plan is not exact journal material"
                )
            self._delete_exact_release_cleanup_target(target)
        if planned_by_identity:
            raise RetentionPlanningError(
                "retention cleanup plan contains a target outside the journal"
            )
        return raw_targets

    def plan_retention(
        self,
        *,
        lock: CrashReleasedFileLock,
        receipts: Sequence[object] = (),
    ) -> RetentionPlan:
        """只形成删除候选；必须有成功 receipt + cleanup_authorized 才返回 target。"""

        lock.assert_held(authority_token=self._authority_token)
        receipt_index = self._receipt_index(receipts)
        histories = self.journals.histories()
        for history in histories.values():
            latest = history[-1]
            if latest["terminal_receipt"] is None:
                continue
            self._resolve_terminal_receipt(latest, receipt_index)
            if latest["phase"] == "cleanup_receipt_committed":
                cleanup_key = (
                    str(latest["reserved_receipt_ids"]["cleanup"]),
                    str(latest["evidence_hashes"]["cleanup_receipt_sha256"]),
                )
                cleanup_receipt = receipt_index.get(cleanup_key)
                if (
                    cleanup_receipt is None
                    or cleanup_receipt["schema_version"]
                    != _identity.CLEANUP_RECEIPT_SCHEMA
                    or cleanup_receipt["attempt_id"] != latest["attempt"]
                    or cleanup_receipt["retained_pair"] != latest["target_pair"]
                    or cleanup_receipt["removed_targets"] != latest["cleanup_targets"]
                ):
                    raise RetentionPlanningError(
                        "cleanup terminal 未绑定 exact typed cleanup receipt/targets"
                    )
        active_journals = [history[-1] for history in histories.values() if not _journal_is_closed(history[-1])]
        if len(active_journals) > 1:
            raise RetentionPlanningError("存在多个活动 deployment attempt")
        journal = active_journals[0] if active_journals else None
        active_record = self.read_active_release()
        binding_record = self.read_local_prior_binding()
        if active_record is None:
            raise RetentionPlanningError("active pointer 缺失")
        active = active_record.value
        inventory = self.release_inventory()
        active_entry = self._entry_for_ref(active["release"], inventory, label="active")
        active_manifest = self._manifest_for_entry(active_entry)

        # bootstrap terminal 是唯一允许 active=R0、binding absent 的中间稳态。
        if binding_record is None:
            closed_bootstraps = [
                history[-1] for history in histories.values()
                if history[-1]["operation"] == "bootstrap_first_pair"
                and history[-1]["phase"] == "terminal_receipt_committed"
            ]
            if len(closed_bootstraps) != 1:
                raise RetentionPlanningError("binding absent 仅允许唯一已封口 bootstrap")
            bootstrap = closed_bootstraps[0]
            bootstrap_receipt = self._resolve_terminal_receipt(bootstrap, receipt_index)
            if journal is None:
                if active["release"] != bootstrap["target_pair"]["active"] or len(inventory) != 1:
                    raise RetentionPlanningError("bootstrap 仅保留 exact R0，不得授权 ingress/cleanup")
                self._assert_release_supports_state(
                    active_manifest,
                    bootstrap_receipt["state_identity"],
                    label="bootstrap R0",
                )
                return RetentionPlan(active_entry, None, None, (), len(inventory), str(bootstrap["attempt"]))

            # bootstrap 后首次普通 R0→R1 在 binding CAS 前仍合法 absent；这不是
            # steady prior authority，也永不产生 cleanup plan。
            phases = _operation_phases(str(journal["operation"]))
            phase = str(journal["phase"])
            if (
                journal["operation"] != "activation"
                or journal["original_pair"]["prior"] is not None
                or journal["binding_cas"]["expected_binding_sha256"] is not None
                or phases.index(phase) >= phases.index("binding_cas_committed")
                or journal["cleanup_targets"]
                or journal["state_plan"]["state_identity_sha256"]
                != bootstrap_receipt["state_identity"]["identity_sha256"]
            ):
                raise RetentionPlanningError(
                    "binding absent 活动 attempt 不是 exact bootstrap 后首次 activation"
                )
            pointer_switched = phases.index(phase) >= phases.index(
                "pointer_cas_committed"
            )
            expected_active = (
                journal["target_pair"]["active"]
                if pointer_switched
                else journal["original_pair"]["active"]
            )
            if active["release"] != expected_active:
                raise RetentionPlanningError(
                    "binding absent 首次 activation pointer 与 phase 漂移"
                )
            allowed_refs = {
                str(journal["original_pair"]["active"]["manifest_sha256"]): journal[
                    "original_pair"
                ]["active"],
                str(journal["candidate"]["manifest_sha256"]): journal["candidate"],
            }
            if len(inventory) > 2 or any(
                entry.manifest_sha256 not in allowed_refs
                or entry.release_id
                != allowed_refs[entry.manifest_sha256]["release_id"]
                for entry in inventory
            ):
                raise RetentionPlanningError(
                    "binding absent 首次 activation 出现第三 retained release"
                )
            others = [
                entry
                for entry in inventory
                if entry.manifest_sha256 != active_entry.manifest_sha256
            ]
            if pointer_switched and not any(
                entry.manifest_sha256
                == journal["original_pair"]["active"]["manifest_sha256"]
                for entry in others
            ):
                raise RetentionPlanningError(
                    "pointer 切换后缺 exact R0 rollback target closure"
                )
            for entry in inventory:
                self._assert_release_supports_state(
                    self._manifest_for_entry(entry),
                    bootstrap_receipt["state_identity"],
                    label="bootstrap 后首次 activation release",
                )
            return RetentionPlan(
                active_entry,
                None,
                others[0] if others else None,
                (),
                len(inventory),
                str(journal["attempt"]),
            )

        binding = binding_record.value
        pointer_switched = False
        binding_switched = False
        if journal is None:
            if active["release"] != binding["active"]:
                raise RetentionPlanningError("终态 active/binding 漂移")
            protected_pair = {"active": binding["active"], "prior": binding["prior"]}
        else:
            if journal["operation"] == "bootstrap_first_pair":
                raise RetentionPlanningError("bootstrap 与 existing binding 冲突")
            phase = str(journal["phase"])
            phases = _operation_phases(str(journal["operation"]))
            pointer_switched = phases.index(phase) >= phases.index(
                "pointer_cas_committed"
            )
            binding_switched = phases.index(phase) >= phases.index(
                "binding_cas_committed"
            )
            protected_pair = (
                journal["target_pair"]
                if pointer_switched
                else journal["original_pair"]
            )
            expected_pointer = protected_pair["active"]
            if active["release"] != expected_pointer:
                raise RetentionPlanningError(
                    "journal phase 与 exact active pointer 不一致"
                )
            expected_binding_pair = (
                journal["target_pair"]
                if binding_switched
                else journal["original_pair"]
            )
            if {
                "active": binding["active"],
                "prior": binding["prior"],
            } != expected_binding_pair:
                raise RetentionPlanningError(
                    "journal phase 与 exact live binding pair 不一致"
                )
            expected_binding_hash = journal["binding_cas"][
                "desired_binding_sha256"
                if binding_switched
                else "expected_binding_sha256"
            ]
            if binding["binding_sha256"] != expected_binding_hash:
                raise RetentionPlanningError(
                    "journal binding CAS hash 与 live binding 不一致"
                )
            if (
                binding["state_identity"]["identity_sha256"]
                != journal["state_plan"]["state_identity_sha256"]
            ):
                raise RetentionPlanningError(
                    "journal state plan 与 live D state identity 不一致"
                )

        if protected_pair["prior"] is None:
            raise RetentionPlanningError("existing binding 流程必须保护 exact prior")
        prior_entry = self._entry_for_ref(
            protected_pair["prior"], inventory, label="protected prior"
        )
        prior_manifest = self._manifest_for_entry(prior_entry)
        binding_active_entry = self._entry_for_ref(
            binding["active"], inventory, label="binding active"
        )
        binding_prior_entry = self._entry_for_ref(
            binding["prior"], inventory, label="binding prior"
        )
        try:
            _identity.lint_local_release_graph(
                release_manifests=[
                    self._manifest_for_entry(binding_active_entry),
                    self._manifest_for_entry(binding_prior_entry),
                ],
                active_release={
                    "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                    "release": binding["active"],
                },
                local_prior_binding=binding,
                retained_release_refs=[binding["active"], binding["prior"]],
            )
        except Exception as error:
            raise RetentionPlanningError(
                "active/prior manifest/state graph 未闭合"
            ) from error
        if {
            "active": binding["active"],
            "prior": binding["prior"],
        } != protected_pair:
            validation_binding = json.loads(
                _identity.canonical_bytes(binding).decode("utf-8")
            )
            validation_binding["binding_id"] = (
                "validation-"
                + _identity.identity_sha256(
                    {"attempt": None if journal is None else journal["attempt"]}
                )
            )
            validation_binding["active"] = protected_pair["active"]
            validation_binding["prior"] = protected_pair["prior"]
            validation_binding["result"] = {
                "status": "bound",
                "pair_sha256": _identity.identity_sha256(protected_pair),
                "retained_release_count": 2,
                "state_policy": "expand_only_no_down_migration",
            }
            validation_binding.pop("binding_sha256", None)
            validation_binding["binding_sha256"] = _identity.identity_sha256(
                validation_binding
            )
            try:
                _identity.lint_local_release_graph(
                    release_manifests=[active_manifest, prior_manifest],
                    active_release={
                        "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                        "release": protected_pair["active"],
                    },
                    local_prior_binding=validation_binding,
                    retained_release_refs=[
                        protected_pair["active"],
                        protected_pair["prior"],
                    ],
                )
            except Exception as error:
                raise RetentionPlanningError(
                    "journal protected pair manifest/state graph 未闭合"
                ) from error
        self._assert_release_supports_state(
            active_manifest,
            binding["state_identity"],
            label="protected active",
        )
        self._assert_release_supports_state(
            prior_manifest,
            binding["state_identity"],
            label="protected prior",
        )
        retained_hashes = {active_entry.manifest_sha256, prior_entry.manifest_sha256}
        extras = [item for item in inventory if item.manifest_sha256 not in retained_hashes]
        if len(extras) > 1:
            raise RetentionPlanningError("活动 attempt 也只允许一棵第三 release")
        if journal is None and extras:
            raise RetentionPlanningError("终态出现第三 retained release")

        transient: ReleaseInventoryEntry | None = None
        cleanup_plans: list[CleanupTargetPlan] = []
        if journal is not None:
            if extras:
                extra = extras[0]
                candidate = journal["candidate"]
                candidate_match = (
                    extra.release_id == candidate["release_id"]
                    and extra.manifest_sha256 == candidate["manifest_sha256"]
                )
                release_cleanup_match = any(
                    raw["kind"] == "release_closure"
                    and raw["release"]["manifest_sha256"] == extra.manifest_sha256
                    and raw["release"]["release_id"] == extra.release_id
                    for raw in journal["cleanup_targets"]
                )
                if candidate_match and not pointer_switched:
                    transient = extra
                elif not release_cleanup_match:
                    raise RetentionPlanningError("第三 release 未被 journal 精确分类")
                elif phase not in {"cleanup_authorized", "cleanup_planned"}:
                    transient = extra

            if phase in {"terminal_receipt_committed", "cleanup_authorized", "cleanup_planned"}:
                receipt = self._resolve_terminal_receipt(journal, receipt_index)
                if receipt["schema_version"] not in {
                    _identity.ACTIVATION_RECEIPT_SCHEMA,
                    _identity.ROLLBACK_RECEIPT_SCHEMA,
                }:
                    raise RetentionPlanningError("cleanup 只能由成功 activation/rollback receipt 授权")
            if phase in {"cleanup_authorized", "cleanup_planned"}:
                for raw in journal["cleanup_targets"]:
                    plan = self._plan_cleanup_target(raw, inventory)
                    if plan is not None:
                        cleanup_plans.append(plan)
            # binding_cas_committed 与 terminal_receipt_committed 均明确返回空计划。

        return RetentionPlan(
            active=active_entry,
            prior=prior_entry,
            transient=transient,
            cleanup_targets=tuple(cleanup_plans),
            release_count=len(inventory),
            active_attempt=None if journal is None else str(journal["attempt"]),
        )


__all__ = [
    "CanonicalJsonRecord",
    "CleanupTargetPlan",
    "CompareAndSwapConflict",
    "CompareAndSwapResult",
    "CrashReleasedFileLock",
    "DEPLOYMENT_ATTEMPT_SCHEMA",
    "DeploymentJournalError",
    "DeploymentJournalStore",
    "DeploymentLockBusy",
    "LocalDeploymentLayout",
    "LocalDeploymentPersistence",
    "LocalDeploymentPersistenceError",
    "LockedBootstrapCommentSchemaExpandAuthorization",
    "LockedExactReleaseClosures",
    "LockedExactScmProcessObservationInput",
    "LockedExactTransientStartAuthorization",
    "LockedVerifiedPhaseCasAuthorization",
    "LockedMutableCanarySqliteSet",
    "LockedWindowsScmProcessHandleTracking",
    "LockedWindowsSteadyScmProcessHandleTracking",
    "LockedWindowsWriterLeaseHandleTracking",
    "LockedWindowsSteadyWriterLeaseHandleTracking",
    "LockedStateSqliteMemoryView",
    "LockedStateSqliteSource",
    "LockedSteadyBootWorkspace",
    "LockedSteadyPairStaticFacts",
    "LockedSteadyReleaseClosures",
    "LockedNewFile",
    "LockedAttemptWorkspace",
    "IncomingCleanupTargetPlan",
    "PartialCleanupTargetPlan",
    "PinnedSqliteSet",
    "PRODUCTION_VM_ROOT_TEXT",
    "ReleaseInventoryEntry",
    "ReleaseCleanupTargetPlan",
    "RetentionPlan",
    "RetentionPlanningError",
    "StateSqliteMemberObservation",
    "UnsafeLocalPath",
    "UnreferencedObjectCleanupTargetPlan",
    "validate_deployment_journal",
    "validate_journal_history",
]
