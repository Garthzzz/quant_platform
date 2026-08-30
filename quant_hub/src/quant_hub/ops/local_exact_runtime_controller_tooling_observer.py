"""Controller-side live observation of the fixed exact-runtime tooling tree.

The persisted tooling manifest remains replayable evidence only.  This module
adds a process-local capability that holds every observed tooling file against
write/delete and overlaps recursive package namespace monitors across every
checkpoint, so an add/remove ABA cannot be hidden between two equal scans.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath

from .local_exact_runtime_tooling import (
    EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
    ExactRuntimeToolingError,
    ExactRuntimeToolingManifest,
    build_exact_runtime_tooling,
    parse_exact_runtime_tooling_bytes,
)
from .local_exact_runtime_tooling_scanner import (
    EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH,
    ExactRuntimeToolingScanError,
    ProductionExactRuntimeToolingVerifier,
    TestOnlyExactRuntimeToolingAdapter,
    _bounded_file_bytes,
    _ExactRuntimeToolingScanner,
    _MAX_MANIFEST_BYTES,
    _WindowsNamespaceChangeMonitor,
    _WindowsReadGuardSet,
)
from .local_exact_runtime_canary_input import LockedExactRuntimeCanaryInput
from .local_deployment_persistence import (
    DeploymentLockBusy,
    LockedSteadyBootWorkspace,
    LockedSteadyPairStaticFacts,
    LockedSteadyReleaseClosures,
)
from .local_release_identity import canonical_bytes


_OBSERVER_TOKEN = object()
_OBSERVATION_TOKEN = object()
_TEST_OBSERVATION_TOKEN = object()
_STEADY_OBSERVATION_TOKEN = object()
_SCHEMA = "qrh-exact-runtime-controller-tooling-observation/v1"
_SCOPE = "controller_tooling_live_observed_not_qualified"
_STEADY_SCHEMA = "qrh-exact-runtime-controller-tooling-observation/v2"
_STEADY_SCOPE = "steady_controller_tooling_live_observed_not_qualified"


class ExactRuntimeControllerToolingObserverError(RuntimeError):
    """The controller could not keep a closed live tooling observation."""


def _path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ExactRuntimeControllerToolingObservationEvidence:
    """Persistent summary only; it cannot restore the live observation."""

    _raw: bytes

    def as_dict(self) -> dict[str, object]:
        try:
            value = json.loads(self._raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling evidence bytes 损坏"
            ) from error
        if type(value) is not dict:
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling evidence 不是 object"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


@dataclass(frozen=True, slots=True)
class SteadyExactRuntimeControllerToolingObservationEvidence:
    """带 steady 身份标签的 closed tooling evidence；不能恢复 live owner。"""

    _raw: bytes

    def as_dict(self) -> dict[str, object]:
        try:
            value = json.loads(self._raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExactRuntimeControllerToolingObserverError(
                "steady controller tooling evidence bytes 损坏"
            ) from error
        if type(value) is not dict:
            raise ExactRuntimeControllerToolingObserverError(
                "steady controller tooling evidence 不是 object"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


def _evidence(
    manifest: ExactRuntimeToolingManifest,
    *,
    checkpoint_generation: int,
) -> ExactRuntimeControllerToolingObservationEvidence:
    if type(manifest) is not ExactRuntimeToolingManifest:
        raise ExactRuntimeControllerToolingObserverError(
            "controller tooling manifest 不是 exact type"
        )
    manifest_raw = manifest.canonical_bytes()
    manifest_document = manifest.as_dict()
    package = manifest_document.get("package")
    python = manifest_document.get("python")
    service_host = manifest_document.get("service_host")
    if type(package) is not dict or type(python) is not dict or type(service_host) is not dict:
        raise ExactRuntimeControllerToolingObserverError(
            "controller tooling manifest 关键结构漂移"
        )
    document: dict[str, object] = {
        "schema_version": _SCHEMA,
        "scope": _SCOPE,
        "tooling_sha256": manifest_document["tooling_sha256"],
        "manifest_sha256": _sha256(manifest_raw),
        "package_inventory_sha256": package["inventory_sha256"],
        "python_sha256": python["sha256"],
        "service_host_sha256": service_host["sha256"],
        "checkpoint_generation": checkpoint_generation,
        "result": "live_observed_not_formally_qualified",
    }
    document["evidence_sha256"] = _sha256(canonical_bytes(document))
    return ExactRuntimeControllerToolingObservationEvidence(
        canonical_bytes(document)
    )


class _LiveToolingCore:
    __slots__ = (
        "_file_guards",
        "_generation",
        "_manifest",
        "_manifest_guard",
        "_monitor",
        "_package_root",
        "_scanner",
        "_state",
    )

    def __init__(self, scanner: _ExactRuntimeToolingScanner):
        if type(scanner) is not _ExactRuntimeToolingScanner:
            raise TypeError("controller tooling core requires exact scanner")
        self._scanner = scanner
        self._state = "prepared"
        self._generation = 0
        self._manifest: ExactRuntimeToolingManifest | None = None
        self._file_guards: _WindowsReadGuardSet | None = None
        self._manifest_guard: _WindowsReadGuardSet | None = None
        self._monitor: _WindowsNamespaceChangeMonitor | None = None
        root = scanner._root  # noqa: SLF001 - 同包 fixed-root scanner capability。
        self._package_root = _path(root, EXACT_RUNTIME_PACKAGE_RELATIVE_PATH)
        manifest_path = _path(
            root, EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH
        )

    def acquire(self) -> None:
        if self._state != "prepared":
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling core acquisition phase 漂移"
            )
        self._state = "acquiring"
        root = self._scanner._root  # noqa: SLF001
        manifest_path = _path(
            root, EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH
        )
        try:
            self._monitor = _WindowsNamespaceChangeMonitor(self._package_root)
            self._manifest_guard = _WindowsReadGuardSet((manifest_path,))
            payload, self._file_guards = self._scanner._snapshot_payload()  # noqa: SLF001
            observed = ExactRuntimeToolingManifest.from_document(
                build_exact_runtime_tooling(payload)
            )
            persisted = parse_exact_runtime_tooling_bytes(
                _bounded_file_bytes(
                    manifest_path, maximum_bytes=_MAX_MANIFEST_BYTES
                )
            )
            if observed.canonical_bytes() != persisted.canonical_bytes():
                raise ExactRuntimeControllerToolingObserverError(
                    "persisted tooling claim 与 controller 现场 bytes 不同"
                )
            self._manifest = observed
            self._state = "live"
            self._checkpoint()
        except BaseException as error:
            self._revoke()
            if self._state == "owner_crash_only":
                raise ExactRuntimeControllerToolingObserverError(
                    "controller tooling acquisition cleanup 结果不明"
                ) from error
            if isinstance(error, ExactRuntimeControllerToolingObserverError):
                raise
            if isinstance(error, (ExactRuntimeToolingError, ExactRuntimeToolingScanError)):
                raise ExactRuntimeControllerToolingObserverError(
                    "controller tooling observation 构造失败"
                ) from error
            raise

    def _close_resource(self, resource: object | None) -> BaseException | None:
        if resource is None:
            return None
        try:
            resource.close()  # type: ignore[attr-defined]
        except BaseException as error:
            return error
        return None

    def _revoke(self, *, force_owner_crash: bool = False) -> None:
        monitor = self._monitor
        file_guards = self._file_guards
        manifest_guard = self._manifest_guard
        self._monitor = None
        self._file_guards = None
        self._manifest_guard = None
        failures = tuple(
            error
            for error in (
                self._close_resource(monitor),
                self._close_resource(file_guards),
                self._close_resource(manifest_guard),
            )
            if error is not None
        )
        self._state = (
            "owner_crash_only"
            if failures or force_owner_crash
            else "revoked"
        )

    def _checkpoint(self) -> ExactRuntimeToolingManifest:
        if self._state != "live" or type(self._manifest) is not ExactRuntimeToolingManifest:
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling observation 已关闭或撤销"
            )
        old_monitor = self._monitor
        if type(old_monitor) is not _WindowsNamespaceChangeMonitor:
            self._revoke()
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling namespace monitor 缺失"
            )
        replacement: _WindowsNamespaceChangeMonitor | None = None
        stage = "replacement_monitor"
        try:
            # The replacement begins before the old monitor is cancelled.  The
            # overlap removes the otherwise unavoidable checkpoint gap.
            replacement = _WindowsNamespaceChangeMonitor(self._package_root)
            stage = "rescan"
            observed = self._scanner.verify(self._manifest)
            self._monitor = replacement
            replacement = None
            stage = "old_monitor_close"
            old_monitor.close()
            self._generation += 1
            return observed
        except BaseException as error:
            replacement_close_error = self._close_resource(replacement)
            message = str(error)
            close_outcome_ambiguous = replacement_close_error is not None or (
                stage == "old_monitor_close"
                and "namespace changed during claim construction" not in message
            ) or (
                stage == "rescan"
                and any(
                    marker in message
                    for marker in (
                        "close failed",
                        "did not close cleanly",
                        "cancellation failed",
                        "completion was inconclusive",
                    )
                )
            )
            self._revoke(force_owner_crash=close_outcome_ambiguous)
            if self._state == "owner_crash_only":
                raise ExactRuntimeControllerToolingObserverError(
                    "controller tooling checkpoint cleanup 结果不明"
                ) from error
            if isinstance(error, ExactRuntimeControllerToolingObserverError):
                raise
            if isinstance(error, (ExactRuntimeToolingError, ExactRuntimeToolingScanError)):
                raise ExactRuntimeControllerToolingObserverError(
                    "controller tooling checkpoint 检出漂移"
                ) from error
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling checkpoint 结果不明"
            ) from error

    def build_evidence(self) -> ExactRuntimeControllerToolingObservationEvidence:
        manifest = self._checkpoint()
        return _evidence(manifest, checkpoint_generation=self._generation)

    def close(self) -> None:
        if self._state == "closed":
            return
        if self._state == "revoked":
            self._state = "closed"
            return
        if self._state == "owner_crash_only":
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling close outcome 已不可判定"
            )
        if self._state == "prepared":
            self._state = "closed"
            return
        self._state = "closing"
        monitor = self._monitor
        file_guards = self._file_guards
        manifest_guard = self._manifest_guard
        self._monitor = None
        self._file_guards = None
        self._manifest_guard = None
        failures = tuple(
            error
            for error in (
                self._close_resource(monitor),
                self._close_resource(file_guards),
                self._close_resource(manifest_guard),
            )
            if error is not None
        )
        if failures:
            self._state = "owner_crash_only"
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling observation close 结果不明"
            ) from failures[0]
        self._state = "closed"


class LockedExactRuntimeControllerToolingObservation:
    """Exact product live tooling capability; never reconstructed from evidence."""

    __slots__ = ("_canary", "_core", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("controller tooling observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("controller tooling observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        core: _LiveToolingCore,
        canary: LockedExactRuntimeCanaryInput,
        *,
        token: object,
    ):
        if (
            token is not _OBSERVATION_TOKEN
            or type(core) is not _LiveToolingCore
            or type(canary) is not LockedExactRuntimeCanaryInput
            or core._state != "prepared"
        ):
            raise TypeError("controller tooling observation provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._core = core
        self._canary = canary
        canary._register_controller_tooling_observation(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("controller tooling observation is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        self._core.build_evidence()
        return _SCOPE

    @property
    def _state(self) -> str:
        return self._core._state  # noqa: SLF001

    def build_evidence(self) -> ExactRuntimeControllerToolingObservationEvidence:
        return self._core.build_evidence()

    def close(self) -> None:
        self._canary._close_controller_tooling_observation_public(  # noqa: SLF001
            self
        )

    def _close_from_canary(self, canary: LockedExactRuntimeCanaryInput) -> None:
        if canary is not self._canary:
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling close owner 漂移"
            )
        self._core.close()
        canary._release_controller_tooling_observation(self)  # noqa: SLF001

    def __enter__(self) -> "LockedExactRuntimeControllerToolingObservation":
        self._core.build_evidence()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedSteadyExactRuntimeControllerToolingObservation:
    """由同一 steady B2 epoch、pair facts 与 release closures 约束的 live tooling。"""

    __slots__ = (
        "_core",
        "_workspace",
        "_facts",
        "_closures",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady controller tooling observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady controller tooling observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        core: _LiveToolingCore,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        *,
        token: object,
    ) -> None:
        if (
            token is not _STEADY_OBSERVATION_TOKEN
            or type(core) is not _LiveToolingCore
            or type(workspace) is not LockedSteadyBootWorkspace
            or type(facts) is not LockedSteadyPairStaticFacts
            or type(closures) is not LockedSteadyReleaseClosures
            or core._state != "prepared"
            or facts._workspace is not workspace  # noqa: SLF001
            or closures._workspace is not workspace  # noqa: SLF001
            or closures._facts is not facts  # noqa: SLF001
        ):
            raise TypeError("steady controller tooling observation provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._core = core
        self._workspace = workspace
        self._facts = facts
        self._closures = closures
        workspace._register_steady_tooling_observation(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady controller tooling observation is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def _state(self) -> str:
        return self._core._state  # noqa: SLF001

    def build_evidence(
        self,
    ) -> SteadyExactRuntimeControllerToolingObservationEvidence:
        self._workspace._assert_live()  # noqa: SLF001
        # tooling 漂移先单调撤销 live core；随后才复核 pair/release facts。
        tooling = self._core.build_evidence().as_dict()
        material = self._facts._assert_live()  # noqa: SLF001
        self._closures._assert_live()  # noqa: SLF001
        if (
            self._facts._workspace is not self._workspace  # noqa: SLF001
            or self._closures._workspace is not self._workspace  # noqa: SLF001
            or self._closures._facts is not self._facts  # noqa: SLF001
        ):
            raise DeploymentLockBusy(
                "steady tooling observation workspace/facts/closures 漂移"
            )
        release = material["release"]
        document: dict[str, object] = {
            "schema_version": _STEADY_SCHEMA,
            "scope": _STEADY_SCOPE,
            "authority_kind": material["authority_kind"],
            "runtime_state_kind": material["runtime_state_kind"],
            "boot_nonce": material["boot_nonce"],
            "active_release_sha256": material["active_release_sha256"],
            "binding_sha256": material["binding_sha256"],
            "retention_aggregate_sha256": material[
                "retention_aggregate_sha256"
            ],
            "state_identity_sha256": material["state_identity_sha256"],
            "release": release,
            "tooling_sha256": tooling["tooling_sha256"],
            "tooling_manifest_sha256": tooling["manifest_sha256"],
            "package_inventory_sha256": tooling[
                "package_inventory_sha256"
            ],
            "python_sha256": tooling["python_sha256"],
            "service_host_sha256": tooling["service_host_sha256"],
            "checkpoint_generation": tooling["checkpoint_generation"],
            "result": "steady_live_observed_not_start_authorization",
        }
        document["evidence_sha256"] = _sha256(canonical_bytes(document))
        return SteadyExactRuntimeControllerToolingObservationEvidence(
            canonical_bytes(document)
        )

    @property
    def scope(self) -> str:
        self.build_evidence()
        return _STEADY_SCOPE

    @property
    def boot_nonce(self) -> str:
        return str(self.build_evidence().as_dict()["boot_nonce"])

    @property
    def tooling_sha256(self) -> str:
        return str(self.build_evidence().as_dict()["tooling_sha256"])

    def close(self) -> None:
        if self._core._state == "closed":  # noqa: SLF001
            return
        self._workspace._close_steady_tooling_observation_public(  # noqa: SLF001
            self
        )

    def _close_from_workspace(
        self, workspace: LockedSteadyBootWorkspace
    ) -> None:
        if workspace is not self._workspace:
            raise ExactRuntimeControllerToolingObserverError(
                "steady controller tooling close owner 漂移"
            )
        self._core.close()
        workspace._release_steady_tooling_observation(self)  # noqa: SLF001

    def __enter__(self) -> "LockedSteadyExactRuntimeControllerToolingObservation":
        self.build_evidence()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class _TestOnlyLockedExactRuntimeControllerToolingObservation:
    __slots__ = ("_core",)

    def __init__(self, core: _LiveToolingCore, *, token: object):
        if token is not _TEST_OBSERVATION_TOKEN or type(core) is not _LiveToolingCore:
            raise TypeError("test-only controller tooling provenance 无效")
        self._core = core

    def build_evidence(self) -> ExactRuntimeControllerToolingObservationEvidence:
        return self._core.build_evidence()

    def close(self) -> None:
        self._core.close()


class ProductionExactRuntimeControllerToolingObserver:
    """No-argument observer for the one fixed production D tooling tree."""

    __slots__ = ("_scanner", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production controller tooling observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production controller tooling observer 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, scanner: _ExactRuntimeToolingScanner, *, token: object):
        if token is not _OBSERVER_TOKEN or type(scanner) is not _ExactRuntimeToolingScanner:
            raise TypeError("production controller tooling observer provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._scanner = scanner
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production controller tooling observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionExactRuntimeControllerToolingObserver":
        verifier = ProductionExactRuntimeToolingVerifier.load_exact_d()
        scanner = verifier._scanner  # noqa: SLF001 - consume exact no-arg loader only.
        if type(scanner) is not _ExactRuntimeToolingScanner:
            raise ExactRuntimeControllerToolingObserverError(
                "production tooling verifier 未返回 exact scanner"
            )
        return cls(scanner, token=_OBSERVER_TOKEN)

    def observe(
        self, canary: LockedExactRuntimeCanaryInput
    ) -> LockedExactRuntimeControllerToolingObservation:
        core = _LiveToolingCore(self._scanner)
        observation = LockedExactRuntimeControllerToolingObservation(
            core, canary, token=_OBSERVATION_TOKEN
        )
        try:
            core.acquire()
            observation.build_evidence()
            return observation
        except BaseException as error:
            try:
                observation.close()
            except BaseException as close_error:
                raise ExactRuntimeControllerToolingObserverError(
                    "controller tooling acquisition cleanup 结果不明"
                ) from close_error
            if isinstance(error, ExactRuntimeControllerToolingObserverError):
                raise
            raise ExactRuntimeControllerToolingObserverError(
                "controller tooling acquisition 未闭合"
            ) from error

    def observe_steady(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
    ) -> LockedSteadyExactRuntimeControllerToolingObservation:
        """观察固定 D tooling，并登记到 exact steady workspace。"""

        core = _LiveToolingCore(self._scanner)
        observation = LockedSteadyExactRuntimeControllerToolingObservation(
            core,
            workspace,
            facts,
            closures,
            token=_STEADY_OBSERVATION_TOKEN,
        )
        try:
            core.acquire()
            observation.build_evidence()
            return observation
        except BaseException as error:
            try:
                observation.close()
            except BaseException as close_error:
                raise ExactRuntimeControllerToolingObserverError(
                    "steady controller tooling acquisition cleanup 结果不明"
                ) from close_error
            if isinstance(error, ExactRuntimeControllerToolingObserverError):
                raise
            raise ExactRuntimeControllerToolingObserverError(
                "steady controller tooling acquisition 未闭合"
            ) from error


class _TestOnlyExactRuntimeControllerToolingObserverAdapter:
    __slots__ = ("_scanner",)

    @classmethod
    def for_test_only(
        cls, root: Path
    ) -> "_TestOnlyExactRuntimeControllerToolingObserverAdapter":
        adapter = TestOnlyExactRuntimeToolingAdapter.for_test_only(root)
        instance = object.__new__(cls)
        instance._scanner = adapter._scanner  # noqa: SLF001 - explicit test seam.
        return instance

    def observe_test_only(
        self,
    ) -> _TestOnlyLockedExactRuntimeControllerToolingObservation:
        core = _LiveToolingCore(self._scanner)
        core.acquire()
        return _TestOnlyLockedExactRuntimeControllerToolingObservation(
            core, token=_TEST_OBSERVATION_TOKEN
        )

    def observe_steady_test_only(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
    ) -> LockedSteadyExactRuntimeControllerToolingObservation:
        core = _LiveToolingCore(self._scanner)
        observation = LockedSteadyExactRuntimeControllerToolingObservation(
            core,
            workspace,
            facts,
            closures,
            token=_STEADY_OBSERVATION_TOKEN,
        )
        try:
            core.acquire()
            observation.build_evidence()
            return observation
        except BaseException as error:
            try:
                observation.close()
            except BaseException as close_error:
                raise ExactRuntimeControllerToolingObserverError(
                    "steady test tooling acquisition cleanup 结果不明"
                ) from close_error
            raise error


__all__ = [
    "ExactRuntimeControllerToolingObservationEvidence",
    "ExactRuntimeControllerToolingObserverError",
    "LockedExactRuntimeControllerToolingObservation",
    "LockedSteadyExactRuntimeControllerToolingObservation",
    "ProductionExactRuntimeControllerToolingObserver",
    "SteadyExactRuntimeControllerToolingObservationEvidence",
]
