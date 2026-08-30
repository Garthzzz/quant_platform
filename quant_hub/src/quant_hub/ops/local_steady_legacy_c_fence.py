"""Steady prelaunch 的固定旧 C 只读现场 fence。

产品入口没有 root、service、PID、path、PowerShell、callback 或 mapping 参数。
它只查询固定 C legacy roots、所有引用这些 roots 的 Windows service/process，
以及生产 8765 listener。结果是同一 steady boot workspace 内的 process-local
能力；closed evidence 不能恢复该能力，也不构成 steady start authorization。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import PureWindowsPath
import subprocess
from typing import Mapping

from .local_deployment_persistence import (
    DeploymentLockBusy,
    LockedSteadyBootWorkspace,
    LockedSteadyPairStaticFacts,
    LockedSteadyReleaseClosures,
)
from .local_exact_runtime_controller_tooling_observer import (
    LockedSteadyExactRuntimeControllerToolingObservation,
)
from .local_release_identity import canonical_bytes
from .local_steady_receipt_lineage import LockedSteadyReceiptLineage


_OBSERVER_TOKEN = object()
_FENCE_TOKEN = object()
_TEST_TOKEN = object()
_SCHEMA = "qrh-steady-legacy-c-prelaunch-live-fence/v1"
_SCOPE = "steady_legacy_c_prelaunch_live_fence_not_start_authorization"
_POWERSHELL = PureWindowsPath(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
_LEGACY_ROOTS = (
    PureWindowsPath(r"C:\quant_platform"),
    PureWindowsPath(r"C:\quant_platform_data"),
)
_PORT = 8765


class SteadyLegacyCFenceError(RuntimeError):
    """无法证明旧 C 在 steady prelaunch 时保持不可写且不占 listener。"""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _rows(value: object, *, label: str) -> tuple[Mapping[str, object], ...]:
    if value is None:
        return ()
    raw = value if type(value) is list else [value]
    if any(type(item) is not dict for item in raw):
        raise SteadyLegacyCFenceError(f"{label} query rows 类型漂移")
    return tuple(raw)  # type: ignore[return-value]


def _mentions_legacy_root(value: object) -> bool:
    if type(value) is not str:
        return False
    normalized = value.replace("/", "\\").casefold()
    return any(
        normalized == str(root).casefold()
        or str(root).casefold() + "\\" in normalized
        for root in _LEGACY_ROOTS
    )


@dataclass(frozen=True, slots=True)
class _LegacyCAbsenceSnapshot:
    services: tuple[tuple[str, str, str, str], ...]
    processes: tuple[tuple[int, str, str], ...]
    listener_pids: tuple[int, ...]

    @classmethod
    def from_query(cls, value: object) -> "_LegacyCAbsenceSnapshot":
        if type(value) is not dict or set(value) != {
            "services",
            "processes",
            "listeners",
        }:
            raise SteadyLegacyCFenceError("旧 C query schema 不闭合")
        services: list[tuple[str, str, str, str]] = []
        for row in _rows(value["services"], label="service"):
            if set(row) != {"name", "state", "start_mode", "path_name"}:
                raise SteadyLegacyCFenceError("旧 C service row schema 不闭合")
            rendered = tuple(str(row[field]) for field in (
                "name",
                "state",
                "start_mode",
                "path_name",
            ))
            if not _mentions_legacy_root(rendered[3]):
                raise SteadyLegacyCFenceError(
                    "product service query 返回了非旧 C root 的第三值"
                )
            if rendered[1].casefold() != "stopped" or rendered[2].casefold() != "disabled":
                raise SteadyLegacyCFenceError(
                    "引用旧 C root 的 service 必须 disabled 且 stopped"
                )
            services.append(rendered)
        processes: list[tuple[int, str, str]] = []
        for row in _rows(value["processes"], label="process"):
            if set(row) != {"pid", "executable_path", "command_line"}:
                raise SteadyLegacyCFenceError("旧 C process row schema 不闭合")
            pid = row["pid"]
            if type(pid) is not int or pid <= 0:
                raise SteadyLegacyCFenceError("旧 C process PID 非法")
            executable = str(row["executable_path"])
            command_line = str(row["command_line"])
            if not (
                _mentions_legacy_root(executable)
                or _mentions_legacy_root(command_line)
            ):
                raise SteadyLegacyCFenceError(
                    "product process query 返回了非旧 C root 的第三值"
                )
            processes.append((pid, executable, command_line))
        listeners: list[int] = []
        raw_listeners = value["listeners"]
        if raw_listeners is not None:
            for raw in raw_listeners if type(raw_listeners) is list else [raw_listeners]:
                if type(raw) is bool:
                    raise SteadyLegacyCFenceError("listener PID 不得是 bool")
                try:
                    pid = int(raw)
                except (TypeError, ValueError) as error:
                    raise SteadyLegacyCFenceError("listener PID 非法") from error
                if pid <= 0:
                    raise SteadyLegacyCFenceError("listener PID 非法")
                listeners.append(pid)
        services.sort(key=lambda item: tuple(part.casefold() for part in item))
        processes.sort(key=lambda item: item[0])
        listeners.sort()
        snapshot = cls(tuple(services), tuple(processes), tuple(listeners))
        if snapshot.processes:
            raise SteadyLegacyCFenceError("仍存在引用旧 C root 的 live process")
        if snapshot.listener_pids:
            raise SteadyLegacyCFenceError(
                "steady prelaunch 要求生产 8765 listener absent"
            )
        return snapshot

    def document(self) -> Mapping[str, object]:
        return {
            "legacy_roots": [str(root) for root in _LEGACY_ROOTS],
            "legacy_services": [
                {
                    "name": name,
                    "state": state,
                    "start_mode": start_mode,
                    "path_name_sha256": hashlib.sha256(
                        path_name.encode("utf-8")
                    ).hexdigest(),
                }
                for name, state, start_mode, path_name in self.services
            ],
            "legacy_process_count": len(self.processes),
            "listener_port": _PORT,
            "listener_pids": list(self.listener_pids),
        }


class _WindowsLegacyCFenceBackend:
    __slots__ = ()

    @staticmethod
    def _query_once() -> _LegacyCAbsenceSnapshot:
        if os.name != "nt":
            raise SteadyLegacyCFenceError("旧 C production live fence 只支持 Windows")
        executable = str(_POWERSHELL)
        if not os.path.isfile(executable):
            raise SteadyLegacyCFenceError("固定 System32 PowerShell 不存在")
        script = r"""
$ErrorActionPreference='Stop'
$roots=@('C:\quant_platform','C:\quant_platform_data')
$services=@(Get-CimInstance Win32_Service | ForEach-Object {
  $p=[string]$_.PathName
  if($roots | Where-Object {$p -match ('(?i)'+[regex]::Escape($_)+'(?:\\|\"|\s|$)')}) {
    @{name=[string]$_.Name;state=[string]$_.State;start_mode=[string]$_.StartMode;path_name=$p}
  }
})
$processes=@(Get-CimInstance Win32_Process | ForEach-Object {
  $e=[string]$_.ExecutablePath;$c=[string]$_.CommandLine
  if($roots | Where-Object {$e -match ('(?i)^'+[regex]::Escape($_)+'(?:\\|$)') -or $c -match ('(?i)'+[regex]::Escape($_)+'(?:\\|\"|\s|$)')}) {
    @{pid=[int64]$_.ProcessId;executable_path=$e;command_line=$c}
  }
})
$listeners=@(Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | Sort-Object)
@{services=$services;processes=$processes;listeners=$listeners}|ConvertTo-Json -Depth 5 -Compress
"""
        result = subprocess.run(
            (
                executable,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=20,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise SteadyLegacyCFenceError("固定旧 C live query 失败")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SteadyLegacyCFenceError("固定旧 C live query JSON 损坏") from error
        return _LegacyCAbsenceSnapshot.from_query(value)

    def observe_absence(self) -> _LegacyCAbsenceSnapshot:
        first = self._query_once()
        second = self._query_once()
        if first != second:
            raise SteadyLegacyCFenceError("旧 C live query 双观察漂移")
        return second


class _TestOnlyLegacyCFenceBackend:
    __slots__ = ("_query",)

    def __init__(self, query: Mapping[str, object]) -> None:
        self._query = json.loads(canonical_bytes(query).decode("utf-8"))

    def replace(self, query: Mapping[str, object]) -> None:
        self._query = json.loads(canonical_bytes(query).decode("utf-8"))

    def observe_absence(self) -> _LegacyCAbsenceSnapshot:
        return _LegacyCAbsenceSnapshot.from_query(self._query)


@dataclass(frozen=True, slots=True)
class SteadyLegacyCPrelaunchFenceEvidence:
    _raw: bytes

    def as_dict(self) -> dict[str, object]:
        try:
            value = json.loads(self._raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SteadyLegacyCFenceError("旧 C fence evidence bytes 损坏") from error
        if type(value) is not dict:
            raise SteadyLegacyCFenceError("旧 C fence evidence 不是 object")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


class LockedSteadyLegacyCPrelaunchFence:
    __slots__ = (
        "_backend",
        "_workspace",
        "_facts",
        "_closures",
        "_tooling",
        "_lineage",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady legacy C prelaunch fence 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady legacy C prelaunch fence 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        backend: object,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        lineage: LockedSteadyReceiptLineage,
        *,
        token: object,
    ) -> None:
        if (
            token is not _FENCE_TOKEN
            or type(backend)
            not in {_WindowsLegacyCFenceBackend, _TestOnlyLegacyCFenceBackend}
            or type(workspace) is not LockedSteadyBootWorkspace
            or type(facts) is not LockedSteadyPairStaticFacts
            or type(closures) is not LockedSteadyReleaseClosures
            or type(tooling)
            is not LockedSteadyExactRuntimeControllerToolingObservation
            or type(lineage) is not LockedSteadyReceiptLineage
            or facts._workspace is not workspace  # noqa: SLF001
            or closures._workspace is not workspace  # noqa: SLF001
            or closures._facts is not facts  # noqa: SLF001
            or tooling._workspace is not workspace  # noqa: SLF001
            or tooling._facts is not facts  # noqa: SLF001
            or tooling._closures is not closures  # noqa: SLF001
            or lineage._workspace is not workspace  # noqa: SLF001
            or lineage._facts is not facts  # noqa: SLF001
            or lineage._closures is not closures  # noqa: SLF001
            or lineage._tooling is not tooling  # noqa: SLF001
        ):
            raise TypeError("steady legacy C prelaunch fence provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._backend = backend
        self._workspace = workspace
        self._facts = facts
        self._closures = closures
        self._tooling = tooling
        self._lineage = lineage
        self._state = "live"
        workspace._register_steady_legacy_c_fence(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady legacy C prelaunch fence is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def build_evidence(self) -> SteadyLegacyCPrelaunchFenceEvidence:
        if self._state != "live":
            raise SteadyLegacyCFenceError("旧 C prelaunch fence 已关闭")
        self._workspace._assert_live()  # noqa: SLF001
        snapshot = self._backend.observe_absence()  # type: ignore[attr-defined]
        tooling = self._tooling.build_evidence().as_dict()
        lineage = self._lineage.build_evidence().as_dict()
        material = self._facts._assert_live()  # noqa: SLF001
        self._closures._assert_live()  # noqa: SLF001
        live_fence = snapshot.document()
        document: dict[str, object] = {
            "schema_version": _SCHEMA,
            "scope": _SCOPE,
            "authority_kind": material["authority_kind"],
            "runtime_state_kind": material["runtime_state_kind"],
            "boot_nonce": material["boot_nonce"],
            "active_release_sha256": material["active_release_sha256"],
            "binding_sha256": material["binding_sha256"],
            "retention_aggregate_sha256": material[
                "retention_aggregate_sha256"
            ],
            "state_identity_sha256": material["state_identity_sha256"],
            "release": material["release"],
            "tooling_evidence_sha256": tooling["evidence_sha256"],
            "receipt_lineage_evidence_sha256": lineage["evidence_sha256"],
            "bootstrap_receipt_sha256": lineage[
                "bootstrap_receipt_sha256"
            ],
            "current_pair_terminal_aggregate_sha256": lineage[
                "current_pair_terminal_aggregate_sha256"
            ],
            "legacy_c_live_fence": live_fence,
            "legacy_c_live_fence_aggregate_sha256": _sha256(live_fence),
            "result": "legacy_c_absent_prelaunch_not_start_authorization",
        }
        document["evidence_sha256"] = _sha256(document)
        return SteadyLegacyCPrelaunchFenceEvidence(canonical_bytes(document))

    @property
    def scope(self) -> str:
        self.build_evidence()
        return _SCOPE

    @property
    def legacy_c_live_fence_aggregate_sha256(self) -> str:
        return str(
            self.build_evidence().as_dict()[
                "legacy_c_live_fence_aggregate_sha256"
            ]
        )

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_steady_legacy_c_fence_public(self)  # noqa: SLF001

    def _close_from_workspace(self, workspace: LockedSteadyBootWorkspace) -> None:
        if workspace is not self._workspace:
            raise SteadyLegacyCFenceError("旧 C prelaunch fence close owner 漂移")
        object.__setattr__(self, "_state", "closed")
        workspace._release_steady_legacy_c_fence(self)  # noqa: SLF001

    def __enter__(self) -> "LockedSteadyLegacyCPrelaunchFence":
        self.build_evidence()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionSteadyLegacyCPrelaunchObserver:
    __slots__ = ("_backend", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production steady legacy C observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production steady legacy C observer 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, backend: _WindowsLegacyCFenceBackend, *, token: object):
        if token is not _OBSERVER_TOKEN or type(backend) is not _WindowsLegacyCFenceBackend:
            raise TypeError("production steady legacy C observer provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._backend = backend
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production steady legacy C observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionSteadyLegacyCPrelaunchObserver":
        if os.name != "nt":
            raise SteadyLegacyCFenceError("production legacy C observer 只支持 Windows")
        return cls(_WindowsLegacyCFenceBackend(), token=_OBSERVER_TOKEN)

    def observe(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        lineage: LockedSteadyReceiptLineage,
    ) -> LockedSteadyLegacyCPrelaunchFence:
        return _observe(
            self._backend, workspace, facts, closures, tooling, lineage
        )


class _TestOnlySteadyLegacyCPrelaunchObserverAdapter:
    __slots__ = ("_backend",)

    @classmethod
    def for_test_only(
        cls, query: Mapping[str, object]
    ) -> "_TestOnlySteadyLegacyCPrelaunchObserverAdapter":
        instance = object.__new__(cls)
        instance._backend = _TestOnlyLegacyCFenceBackend(query)
        return instance

    def replace(self, query: Mapping[str, object]) -> None:
        self._backend.replace(query)

    def observe_test_only(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        lineage: LockedSteadyReceiptLineage,
    ) -> LockedSteadyLegacyCPrelaunchFence:
        return _observe(
            self._backend, workspace, facts, closures, tooling, lineage
        )


def _observe(
    backend: object,
    workspace: LockedSteadyBootWorkspace,
    facts: LockedSteadyPairStaticFacts,
    closures: LockedSteadyReleaseClosures,
    tooling: LockedSteadyExactRuntimeControllerToolingObservation,
    lineage: LockedSteadyReceiptLineage,
) -> LockedSteadyLegacyCPrelaunchFence:
    fence = LockedSteadyLegacyCPrelaunchFence(
        backend,
        workspace,
        facts,
        closures,
        tooling,
        lineage,
        token=_FENCE_TOKEN,
    )
    try:
        fence.build_evidence()
        return fence
    except BaseException as error:
        try:
            fence.close()
        except BaseException as close_error:
            raise SteadyLegacyCFenceError(
                "旧 C prelaunch fence acquisition cleanup 未闭合"
            ) from close_error
        raise error


__all__ = [
    "LockedSteadyLegacyCPrelaunchFence",
    "ProductionSteadyLegacyCPrelaunchObserver",
    "SteadyLegacyCFenceError",
    "SteadyLegacyCPrelaunchFenceEvidence",
]
