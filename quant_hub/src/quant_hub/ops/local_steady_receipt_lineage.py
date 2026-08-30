"""Steady 启动所需的 durable bootstrap/current-pair receipt lineage。

该模块只在同一 B2 steady workspace 内读取固定 ``audit/receipts``，把每个
canonical receipt 与 closed deployment journal 的 reserved/terminal hash 逐项闭合，
并持续持有 receipt 文件与目录 namespace。它不选择 current；current 仍只来自
active pointer + binding。返回的 closed evidence 也不是启动授权。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Mapping, Sequence

from . import local_release_identity as _identity
from .local_deployment_persistence import (
    DeploymentLockBusy,
    LocalDeploymentPersistence,
    LockedSteadyBootWorkspace,
    LockedSteadyPairStaticFacts,
    LockedSteadyReleaseClosures,
    RetentionPlanningError,
)
from .local_exact_runtime_controller_tooling_observer import (
    LockedSteadyExactRuntimeControllerToolingObservation,
)
from .local_exact_runtime_tooling_scanner import (
    ExactRuntimeToolingScanError,
    _bounded_file_bytes,
    _WindowsNamespaceChangeMonitor,
    _WindowsReadGuardSet,
)


_OBSERVER_TOKEN = object()
_LINEAGE_TOKEN = object()
_TEST_TOKEN = object()
_SCHEMA = "qrh-steady-receipt-lineage/v1"
_SCOPE = "steady_receipt_lineage_live_observed_not_start_authorization"
_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.json$")
_MAX_RECEIPT_BYTES = 4 * 1024 * 1024
_MAX_RECEIPTS = 10_000


class SteadyReceiptLineageError(RuntimeError):
    """Receipt namespace、journal binding 或 current lineage 无法闭合。"""


def _sha256(value: object) -> str:
    return hashlib.sha256(_identity.canonical_bytes(value)).hexdigest()


def _closed_receipt(path: Path) -> Mapping[str, object]:
    try:
        raw = _bounded_file_bytes(path, maximum_bytes=_MAX_RECEIPT_BYTES)
        parsed = json.loads(raw.decode("utf-8"))
        receipt = _identity.validate_local_receipt(parsed)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _identity.LocalReleaseIdentityError,
        ExactRuntimeToolingScanError,
    ) as error:
        raise SteadyReceiptLineageError("receipt canonical/schema 读取失败") from error
    if raw != _identity.canonical_bytes(receipt):
        raise SteadyReceiptLineageError("receipt bytes 不是 exact canonical JSON")
    match = _NAME_RE.fullmatch(path.name)
    if match is None or match.group(1) != receipt["receipt_id"]:
        raise SteadyReceiptLineageError("receipt filename 与 receipt_id 不一致")
    return receipt


def _receipt_paths(root: Path) -> tuple[Path, ...]:
    try:
        entries = tuple(sorted(os.scandir(root), key=lambda item: item.name))
    except OSError as error:
        raise SteadyReceiptLineageError("无法枚举 fixed receipt root") from error
    if len(entries) > _MAX_RECEIPTS:
        raise SteadyReceiptLineageError("receipt inventory 超过固定上限")
    folded: dict[str, str] = {}
    paths: list[Path] = []
    for entry in entries:
        match = _NAME_RE.fullmatch(entry.name)
        if match is None:
            raise SteadyReceiptLineageError("receipt root 含非合同成员")
        receipt_id = match.group(1)
        previous = folded.get(receipt_id.casefold())
        if previous is not None and previous != receipt_id:
            raise SteadyReceiptLineageError("receipt filename 存在 case-fold 碰撞")
        folded[receipt_id.casefold()] = receipt_id
        paths.append(root / entry.name)
    return tuple(paths)


def _closed_receipts(
    root: Path,
    paths: Sequence[Path],
) -> tuple[Mapping[str, object], ...]:
    if tuple(paths) != _receipt_paths(root):
        raise SteadyReceiptLineageError("receipt namespace 在 guarded scan 前漂移")
    receipts = tuple(_closed_receipt(path) for path in paths)
    if tuple(paths) != _receipt_paths(root):
        raise SteadyReceiptLineageError("receipt namespace 在 guarded scan 后漂移")
    return receipts


def _derive_lineage(
    persistence: LocalDeploymentPersistence,
    facts: LockedSteadyPairStaticFacts,
    receipts: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    active = persistence.journals.active_revisions()
    recovery = facts._workspace.failure_recovery_authorization  # noqa: SLF001
    if active and (
        len(active) != 1
        or recovery is None
        or recovery["journal_sha256"] != active[0]["journal_sha256"]
    ):
        raise SteadyReceiptLineageError(
            "active journal 未被同一 steady failure recovery workspace 授权"
        )
    if not active and recovery is not None:
        raise SteadyReceiptLineageError(
            "closed journal 不得继续派生 failure recovery lineage"
        )
    histories = persistence.journals.histories()
    by_id = {str(receipt["receipt_id"]): receipt for receipt in receipts}
    if len(by_id) != len(receipts):
        raise SteadyReceiptLineageError("receipt_id 重复")

    reserved: dict[str, tuple[Mapping[str, object], str]] = {}
    terminal_refs: dict[str, Mapping[str, object]] = {}
    cleanup_hashes: dict[str, str] = {}
    for history in histories.values():
        first = history[0]
        latest = history[-1]
        attempt = str(first["attempt"])
        for kind, raw_id in first["reserved_receipt_ids"].items():
            if raw_id is None:
                continue
            receipt_id = str(raw_id)
            if receipt_id in reserved:
                raise SteadyReceiptLineageError("journal reserved receipt ID 重复")
            reserved[receipt_id] = (latest, str(kind))
        terminal = latest.get("terminal_receipt")
        if isinstance(terminal, Mapping):
            terminal_refs[str(terminal["receipt_id"])] = terminal
        cleanup_id = first["reserved_receipt_ids"].get("cleanup")
        cleanup_sha = latest["evidence_hashes"].get("cleanup_receipt_sha256")
        if cleanup_id is not None and cleanup_sha is not None:
            cleanup_hashes[str(cleanup_id)] = str(cleanup_sha)
        if str(latest["attempt"]) != attempt:
            raise SteadyReceiptLineageError("journal history attempt 漂移")

    for receipt_id, receipt in by_id.items():
        reservation = reserved.get(receipt_id)
        if reservation is None:
            raise SteadyReceiptLineageError("receipt 未被 durable journal 预留")
        schema = receipt["schema_version"]
        if schema == _identity.CLEANUP_RECEIPT_SCHEMA:
            if cleanup_hashes.get(receipt_id) != receipt["receipt_sha256"]:
                raise SteadyReceiptLineageError(
                    "cleanup receipt 未被 closed journal hash 绑定"
                )
        else:
            terminal = terminal_refs.get(receipt_id)
            if (
                not isinstance(terminal, Mapping)
                or terminal.get("receipt_sha256") != receipt["receipt_sha256"]
            ):
                raise SteadyReceiptLineageError(
                    "terminal receipt 未被 closed journal exact 引用"
                )

    for receipt_id, terminal in terminal_refs.items():
        receipt = by_id.get(receipt_id)
        if receipt is None or receipt["receipt_sha256"] != terminal["receipt_sha256"]:
            raise SteadyReceiptLineageError("closed journal terminal receipt 缺失")
    for receipt_id, expected_hash in cleanup_hashes.items():
        receipt = by_id.get(receipt_id)
        if receipt is None or receipt["receipt_sha256"] != expected_hash:
            raise SteadyReceiptLineageError("closed journal cleanup receipt 缺失")

    bootstraps = tuple(
        receipt
        for receipt in receipts
        if receipt["schema_version"] == _identity.ACTIVATION_RECEIPT_SCHEMA
        and receipt["operation"] == "bootstrap_first_pair"
    )
    if len(bootstraps) != 1:
        raise SteadyReceiptLineageError("steady lineage 要求恰一 bootstrap terminal receipt")
    bootstrap = bootstraps[0]
    proof = bootstrap["proof"]
    if (
        proof["legacy_c_writer_status"] != "fenced"
        or proof["ingress_status"] != "closed"
    ):
        raise SteadyReceiptLineageError("bootstrap 未绑定旧 C writer fence/closed ingress")

    material = facts._assert_live()  # noqa: SLF001
    current_pair = {
        "active": material["release"],
        "prior": material["prior_release"],
    }
    current_terminals = tuple(
        receipt
        for receipt in receipts
        if receipt["schema_version"]
        in {
            _identity.ACTIVATION_RECEIPT_SCHEMA,
            _identity.ROLLBACK_RECEIPT_SCHEMA,
        }
        and receipt["pair"] == current_pair
        and (
            receipt["operation"] != "bootstrap_first_pair"
            or current_pair["prior"] is None
        )
    )
    if not current_terminals:
        raise SteadyReceiptLineageError(
            "当前 active/prior pair 缺 exact success terminal receipt"
        )
    current_material = sorted(
        (
            {
                "attempt_id": receipt["attempt_id"],
                "receipt_id": receipt["receipt_id"],
                "receipt_sha256": receipt["receipt_sha256"],
                "operation": receipt["operation"],
                "controller_verification_sha256": receipt["result"].get(
                    "controller_verification_sha256",
                    receipt["result"].get("proof_sha256"),
                ),
            }
            for receipt in current_terminals
        ),
        key=lambda item: (str(item["receipt_id"]), str(item["receipt_sha256"])),
    )
    inventory = sorted(
        (
            {
                "receipt_id": receipt["receipt_id"],
                "receipt_sha256": receipt["receipt_sha256"],
                "schema_version": receipt["schema_version"],
                "attempt_id": receipt["attempt_id"],
            }
            for receipt in receipts
        ),
        key=lambda item: (str(item["receipt_id"]), str(item["receipt_sha256"])),
    )
    return {
        "authority_kind": material["authority_kind"],
        "runtime_state_kind": material["runtime_state_kind"],
        "boot_nonce": material["boot_nonce"],
        "active_release_sha256": material["active_release_sha256"],
        "binding_sha256": material["binding_sha256"],
        "retention_aggregate_sha256": material["retention_aggregate_sha256"],
        "state_identity_sha256": material["state_identity_sha256"],
        "release": material["release"],
        "bootstrap_receipt_sha256": bootstrap["receipt_sha256"],
        "bootstrap_writer_fence_sha256": proof["writer_fence_sha256"],
        "current_pair_terminal_count": len(current_material),
        "current_pair_terminal_aggregate_sha256": _sha256(current_material),
        "receipt_inventory_count": len(inventory),
        "receipt_inventory_aggregate_sha256": _sha256(inventory),
    }


class _ReceiptLineageCore:
    __slots__ = (
        "_persistence",
        "_facts",
        "_root",
        "_paths",
        "_guards",
        "_monitor",
        "_material_raw",
        "_generation",
        "_state",
    )

    def __init__(
        self,
        persistence: LocalDeploymentPersistence,
        facts: LockedSteadyPairStaticFacts,
    ) -> None:
        self._persistence = persistence
        self._facts = facts
        self._root = persistence.layout.receipts
        self._paths: tuple[Path, ...] = ()
        self._guards: _WindowsReadGuardSet | None = None
        self._monitor: _WindowsNamespaceChangeMonitor | None = None
        self._material_raw = b""
        self._generation = 0
        self._state = "prepared"

    @staticmethod
    def _close(resource: object | None) -> BaseException | None:
        if resource is None:
            return None
        try:
            resource.close()  # type: ignore[attr-defined]
        except BaseException as error:
            return error
        return None

    @staticmethod
    def _known_namespace_change(error: BaseException | None) -> bool:
        return error is not None and (
            "namespace changed during claim construction" in str(error)
            or "receipt inventory 持续期间漂移" in str(error)
            or "receipt namespace" in str(error)
        )

    def acquire(self) -> None:
        if self._state != "prepared":
            raise SteadyReceiptLineageError("receipt lineage acquisition state 漂移")
        self._state = "acquiring"
        try:
            self._monitor = _WindowsNamespaceChangeMonitor(self._root)
            paths = _receipt_paths(self._root)
            self._guards = _WindowsReadGuardSet(paths)
            receipts = _closed_receipts(self._root, paths)
            material = _derive_lineage(self._persistence, self._facts, receipts)
            self._paths = paths
            self._material_raw = _identity.canonical_bytes(material)
            self._state = "live"
            self.checkpoint()
        except BaseException as error:
            monitor_error = self._close(self._monitor)
            guard_error = self._close(self._guards)
            self._monitor = None
            self._guards = None
            self._state = (
                "owner_crash_only"
                if guard_error is not None
                or (
                    monitor_error is not None
                    and not self._known_namespace_change(monitor_error)
                )
                else "revoked"
            )
            if self._state == "owner_crash_only":
                raise SteadyReceiptLineageError(
                    "receipt lineage acquisition cleanup 结果不明"
                ) from (monitor_error or guard_error)
            raise error

    def checkpoint(self) -> Mapping[str, object]:
        if self._state != "live":
            raise SteadyReceiptLineageError("receipt lineage 已关闭或撤销")
        old_monitor = self._monitor
        old_guards = self._guards
        replacement_monitor: _WindowsNamespaceChangeMonitor | None = None
        replacement_guards: _WindowsReadGuardSet | None = None
        try:
            replacement_monitor = _WindowsNamespaceChangeMonitor(self._root)
            paths = _receipt_paths(self._root)
            if paths != self._paths:
                raise SteadyReceiptLineageError("receipt inventory 持续期间漂移")
            replacement_guards = _WindowsReadGuardSet(paths)
            receipts = _closed_receipts(self._root, paths)
            material = _derive_lineage(self._persistence, self._facts, receipts)
            if _identity.canonical_bytes(material) != self._material_raw:
                raise SteadyReceiptLineageError("receipt lineage material 漂移")
            old_monitor_error = self._close(old_monitor)
            old_monitor = None
            old_guard_error = self._close(old_guards)
            old_guards = None
            if old_monitor_error is not None or old_guard_error is not None:
                if old_guard_error is not None or not self._known_namespace_change(
                    old_monitor_error
                ):
                    raise SteadyReceiptLineageError(
                        "receipt lineage old guard close 结果不明"
                    ) from (old_guard_error or old_monitor_error)
                raise SteadyReceiptLineageError(
                    "receipt namespace 自上次 checkpoint 后发生漂移"
                ) from old_monitor_error
            self._monitor = replacement_monitor
            self._guards = replacement_guards
            replacement_monitor = None
            replacement_guards = None
            self._generation += 1
            return material
        except BaseException as error:
            replacement_errors = (
                self._close(replacement_monitor),
                self._close(replacement_guards),
            )
            old_errors = (self._close(old_monitor), self._close(old_guards))
            self._monitor = None
            self._guards = None
            self._state = (
                "owner_crash_only"
                if any(
                    item is not None
                    and not self._known_namespace_change(item)
                    for item in (*replacement_errors, *old_errors)
                )
                else "revoked"
            )
            if self._state == "owner_crash_only":
                raise SteadyReceiptLineageError(
                    "receipt lineage checkpoint cleanup 结果不明"
                ) from error
            if isinstance(error, SteadyReceiptLineageError):
                raise
            raise SteadyReceiptLineageError("receipt lineage checkpoint 失败") from error

    def close(self) -> None:
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise SteadyReceiptLineageError("receipt lineage 只允许进程退出回收")
        if self._state == "revoked":
            self._state = "closed"
            return
        errors = (self._close(self._monitor), self._close(self._guards))
        self._monitor = None
        self._guards = None
        if any(error is not None for error in errors):
            self._state = "owner_crash_only"
            raise SteadyReceiptLineageError("receipt lineage close 结果不明") from next(
                error for error in errors if error is not None
            )
        self._state = "closed"


@dataclass(frozen=True, slots=True)
class SteadyReceiptLineageEvidence:
    _raw: bytes

    def as_dict(self) -> dict[str, object]:
        try:
            value = json.loads(self._raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SteadyReceiptLineageError("receipt lineage evidence bytes 损坏") from error
        if type(value) is not dict:
            raise SteadyReceiptLineageError("receipt lineage evidence 不是 object")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


class LockedSteadyReceiptLineage:
    __slots__ = (
        "_core",
        "_persistence",
        "_workspace",
        "_facts",
        "_closures",
        "_tooling",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady receipt lineage 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady receipt lineage 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        core: _ReceiptLineageCore,
        persistence: LocalDeploymentPersistence,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        *,
        token: object,
    ) -> None:
        if (
            token is not _LINEAGE_TOKEN
            or type(core) is not _ReceiptLineageCore
            or type(persistence) is not LocalDeploymentPersistence
            or type(workspace) is not LockedSteadyBootWorkspace
            or type(facts) is not LockedSteadyPairStaticFacts
            or type(closures) is not LockedSteadyReleaseClosures
            or type(tooling)
            is not LockedSteadyExactRuntimeControllerToolingObservation
            or facts._persistence is not persistence  # noqa: SLF001
            or facts._workspace is not workspace  # noqa: SLF001
            or closures._workspace is not workspace  # noqa: SLF001
            or closures._facts is not facts  # noqa: SLF001
            or tooling._workspace is not workspace  # noqa: SLF001
            or tooling._facts is not facts  # noqa: SLF001
            or tooling._closures is not closures  # noqa: SLF001
        ):
            raise TypeError("steady receipt lineage provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._core = core
        self._persistence = persistence
        self._workspace = workspace
        self._facts = facts
        self._closures = closures
        self._tooling = tooling
        workspace._register_steady_receipt_lineage(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady receipt lineage is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def _state(self) -> str:
        return self._core._state  # noqa: SLF001

    def build_evidence(self) -> SteadyReceiptLineageEvidence:
        self._workspace._assert_live()  # noqa: SLF001
        material = self._core.checkpoint()
        tooling = self._tooling.build_evidence().as_dict()
        self._closures._assert_live()  # noqa: SLF001
        document = {
            "schema_version": _SCHEMA,
            "scope": _SCOPE,
            **material,
            "tooling_evidence_sha256": tooling["evidence_sha256"],
            "checkpoint_generation": self._core._generation,  # noqa: SLF001
            "result": "lineage_live_observed_not_start_authorization",
        }
        document["evidence_sha256"] = _sha256(document)
        return SteadyReceiptLineageEvidence(_identity.canonical_bytes(document))

    @property
    def scope(self) -> str:
        self.build_evidence()
        return _SCOPE

    @property
    def receipt_inventory_aggregate_sha256(self) -> str:
        return str(
            self.build_evidence().as_dict()["receipt_inventory_aggregate_sha256"]
        )

    def close(self) -> None:
        if self._core._state == "closed":  # noqa: SLF001
            return
        self._workspace._close_steady_receipt_lineage_public(self)  # noqa: SLF001

    def _close_from_workspace(self, workspace: LockedSteadyBootWorkspace) -> None:
        if workspace is not self._workspace:
            raise SteadyReceiptLineageError("receipt lineage close owner 漂移")
        self._core.close()
        workspace._release_steady_receipt_lineage(self)  # noqa: SLF001

    def __enter__(self) -> "LockedSteadyReceiptLineage":
        self.build_evidence()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionSteadyReceiptLineageObserver:
    __slots__ = ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production steady receipt lineage observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production steady receipt lineage observer 不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _OBSERVER_TOKEN:
            raise TypeError("production steady receipt lineage observer provenance 无效")
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production steady receipt lineage observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionSteadyReceiptLineageObserver":
        return cls(token=_OBSERVER_TOKEN)

    def observe(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
    ) -> LockedSteadyReceiptLineage:
        persistence = facts._persistence  # noqa: SLF001
        if persistence._test_only:  # noqa: SLF001
            raise DeploymentLockBusy("product receipt lineage 不接受 test-only root")
        return _observe(persistence, workspace, facts, closures, tooling)


class _TestOnlySteadyReceiptLineageObserverAdapter:
    __slots__ = ()

    @classmethod
    def for_test_only(cls) -> "_TestOnlySteadyReceiptLineageObserverAdapter":
        return cls()

    def observe_test_only(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
    ) -> LockedSteadyReceiptLineage:
        persistence = facts._persistence  # noqa: SLF001
        if not persistence._test_only:  # noqa: SLF001
            raise DeploymentLockBusy("test receipt lineage 只接受 test-only root")
        return _observe(persistence, workspace, facts, closures, tooling)


def _observe(
    persistence: LocalDeploymentPersistence,
    workspace: LockedSteadyBootWorkspace,
    facts: LockedSteadyPairStaticFacts,
    closures: LockedSteadyReleaseClosures,
    tooling: LockedSteadyExactRuntimeControllerToolingObservation,
) -> LockedSteadyReceiptLineage:
    core = _ReceiptLineageCore(persistence, facts)
    lineage = LockedSteadyReceiptLineage(
        core,
        persistence,
        workspace,
        facts,
        closures,
        tooling,
        token=_LINEAGE_TOKEN,
    )
    try:
        core.acquire()
        lineage.build_evidence()
        return lineage
    except BaseException as error:
        try:
            lineage.close()
        except BaseException as close_error:
            raise SteadyReceiptLineageError(
                "receipt lineage acquisition cleanup 未闭合"
            ) from close_error
        raise error


__all__ = [
    "LockedSteadyReceiptLineage",
    "ProductionSteadyReceiptLineageObserver",
    "SteadyReceiptLineageError",
    "SteadyReceiptLineageEvidence",
]
