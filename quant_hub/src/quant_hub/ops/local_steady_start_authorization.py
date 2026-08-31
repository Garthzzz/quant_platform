"""由同一 steady live chain 派生 exact start authorization 与 SCM v2 计划。"""

from __future__ import annotations

import json
from typing import Mapping

from . import local_release_identity as _identity
from .local_deployment_persistence import (
    DeploymentLockBusy,
    LockedSteadyBootWorkspace,
    LockedSteadyPairStaticFacts,
    LockedSteadyReleaseClosures,
)
from .local_exact_runtime_controller_tooling_observer import (
    LockedSteadyExactRuntimeControllerToolingObservation,
)
from .local_steady_legacy_c_fence import (
    LockedSteadyLegacyCPrelaunchFence,
)
from .local_steady_receipt_lineage import LockedSteadyReceiptLineage


_AUTHORIZER_TOKEN = object()
_AUTHORIZATION_TOKEN = object()
_SCM_INPUT_TOKEN = object()
_TEST_TOKEN = object()
_AUTHORIZATION_SCHEMA = "qrh-exact-steady-start-authorization/v1"
_AUTHORIZATION_SCOPE = "exact_steady_start_authorization_input_only"
_PLAN_SCHEMA = "qrh-exact-steady-scm-start-plan/v1"
_PLAN_SCOPE = "exact_steady_scm_start_plan_input_only"
_SCM_INPUT_SCOPE = "exact_steady_scm_process_observation_input_only"
_SERVICE_NAME = "QuantResearchHub"
_SCM_HOST_EXECUTABLE = (
    r"D:\quant\quant_platform\tooling\python\pythonservice.exe"
)
_SCM_PYTHON_CLASS = "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
_CHILD_EXECUTABLE = r"D:\quant\quant_platform\tooling\python\python.exe"
_CHILD_MODULE = "quant_hub.ops.local_exact_runtime_entry"
_PYCACHE_PARENT = r"D:\quant\quant_platform\tmp\service\pycache"


class ExactSteadyStartAuthorizationError(RuntimeError):
    """Steady live chain 不能形成或继续维持 exact start authorization。"""


def _clone(value: object) -> object:
    return json.loads(_identity.canonical_bytes(value).decode("utf-8"))


def _derive_material(
    workspace: LockedSteadyBootWorkspace,
    facts: LockedSteadyPairStaticFacts,
    closures: LockedSteadyReleaseClosures,
    tooling: LockedSteadyExactRuntimeControllerToolingObservation,
    lineage: LockedSteadyReceiptLineage,
    legacy_c_fence: LockedSteadyLegacyCPrelaunchFence,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    workspace._assert_live()  # noqa: SLF001
    if (
        facts._workspace is not workspace  # noqa: SLF001
        or closures._workspace is not workspace  # noqa: SLF001
        or closures._facts is not facts  # noqa: SLF001
        or tooling._workspace is not workspace  # noqa: SLF001
        or tooling._facts is not facts  # noqa: SLF001
        or tooling._closures is not closures  # noqa: SLF001
        or lineage._workspace is not workspace  # noqa: SLF001
        or lineage._facts is not facts  # noqa: SLF001
        or lineage._closures is not closures  # noqa: SLF001
        or lineage._tooling is not tooling  # noqa: SLF001
        or legacy_c_fence._workspace is not workspace  # noqa: SLF001
        or legacy_c_fence._facts is not facts  # noqa: SLF001
        or legacy_c_fence._closures is not closures  # noqa: SLF001
        or legacy_c_fence._tooling is not tooling  # noqa: SLF001
        or legacy_c_fence._lineage is not lineage  # noqa: SLF001
    ):
        raise DeploymentLockBusy("steady start live chain workspace provenance 漂移")
    # 最外层 old-C evidence 会按序重放 lineage、tooling、release 与 static facts。
    old_c = legacy_c_fence.build_evidence().as_dict()
    lineage_evidence = lineage.build_evidence().as_dict()
    tooling_evidence = tooling.build_evidence().as_dict()
    closures._assert_live()  # noqa: SLF001
    static = facts._assert_live()  # noqa: SLF001
    release = static["release"]
    if type(release) is not dict:
        release = _clone(release)
    if type(release) is not dict:
        raise ExactSteadyStartAuthorizationError("steady active release ref 漂移")
    boot_nonce = str(static["boot_nonce"])
    pycache_prefix = _PYCACHE_PARENT + "\\" + boot_nonce
    runtime_arguments = [
        "--authority-kind",
        "steady_active",
        "--runtime-state-kind",
        "steady_current",
        "--boot-nonce",
        boot_nonce,
        "--active-release-sha256",
        str(static["active_release_sha256"]),
        "--binding-sha256",
        str(static["binding_sha256"]),
        "--retention-aggregate-sha256",
        str(static["retention_aggregate_sha256"]),
        "--state-identity-sha256",
        str(static["state_identity_sha256"]),
        "--release-id",
        str(release["release_id"]),
        "--manifest-sha256",
        str(release["manifest_sha256"]),
        "--tooling-sha256",
        str(tooling_evidence["tooling_sha256"]),
        "--receipt-lineage-aggregate-sha256",
        str(lineage_evidence["receipt_inventory_aggregate_sha256"]),
        "--legacy-c-live-fence-aggregate-sha256",
        str(old_c["legacy_c_live_fence_aggregate_sha256"]),
    ]
    service_arguments = ["steady-exact-runtime", *runtime_arguments]
    child_argv = [
        _CHILD_EXECUTABLE,
        "-I",
        "-B",
        "-X",
        "utf8",
        "-X",
        "pycache_prefix=" + pycache_prefix,
        "-m",
        _CHILD_MODULE,
        *runtime_arguments,
    ]
    plan: dict[str, object] = {
        "schema_version": _PLAN_SCHEMA,
        "scope": _PLAN_SCOPE,
        "authority_kind": "steady_active",
        "runtime_state_kind": "steady_current",
        "boot_nonce": boot_nonce,
        "active_release_sha256": static["active_release_sha256"],
        "binding_sha256": static["binding_sha256"],
        "retention_aggregate_sha256": static["retention_aggregate_sha256"],
        "state_identity_sha256": static["state_identity_sha256"],
        "release": release,
        "tooling_sha256": tooling_evidence["tooling_sha256"],
        "receipt_lineage_aggregate_sha256": lineage_evidence[
            "receipt_inventory_aggregate_sha256"
        ],
        "legacy_c_live_fence_aggregate_sha256": old_c[
            "legacy_c_live_fence_aggregate_sha256"
        ],
        "service": {
            "service_name": _SERVICE_NAME,
            "binary_path": _SCM_HOST_EXECUTABLE,
            "python_class": _SCM_PYTHON_CLASS,
            "start_type": "automatic",
            "start_arguments": service_arguments,
        },
        "child": {
            "executable": _CHILD_EXECUTABLE,
            "module": _CHILD_MODULE,
            "argv": child_argv,
        },
    }
    plan_sha256 = _identity.identity_sha256(plan)
    authorization: dict[str, object] = {
        "schema_version": _AUTHORIZATION_SCHEMA,
        "scope": _AUTHORIZATION_SCOPE,
        "authority_kind": "steady_active",
        "runtime_state_kind": "steady_current",
        "boot_nonce": boot_nonce,
        "active_release_sha256": static["active_release_sha256"],
        "binding_sha256": static["binding_sha256"],
        "retention_aggregate_sha256": static["retention_aggregate_sha256"],
        "state_identity_sha256": static["state_identity_sha256"],
        "release": release,
        "tooling_sha256": tooling_evidence["tooling_sha256"],
        "receipt_lineage_aggregate_sha256": lineage_evidence[
            "receipt_inventory_aggregate_sha256"
        ],
        "legacy_c_live_fence_aggregate_sha256": old_c[
            "legacy_c_live_fence_aggregate_sha256"
        ],
        "scm_identity_sha256": plan_sha256,
    }
    return plan, authorization


class LockedExactSteadyStartAuthorization:
    """同 epoch live chain 的 provisional steady launch capability。"""

    __slots__ = (
        "_workspace",
        "_facts",
        "_closures",
        "_tooling",
        "_lineage",
        "_legacy_c_fence",
        "_plan_raw",
        "_authorization_raw",
        "_authorization_sha256",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact steady start authorization 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact steady start authorization 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        lineage: LockedSteadyReceiptLineage,
        legacy_c_fence: LockedSteadyLegacyCPrelaunchFence,
        *,
        token: object,
    ) -> None:
        if token is not _AUTHORIZATION_TOKEN:
            raise TypeError("exact steady start authorization provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._workspace = workspace
        self._facts = facts
        self._closures = closures
        self._tooling = tooling
        self._lineage = lineage
        self._legacy_c_fence = legacy_c_fence
        plan, authorization = _derive_material(
            workspace, facts, closures, tooling, lineage, legacy_c_fence
        )
        self._plan_raw = _identity.canonical_bytes(plan)
        self._authorization_raw = _identity.canonical_bytes(authorization)
        self._authorization_sha256 = _identity.identity_sha256(authorization)
        self._state = "live"
        workspace._register_steady_start_authorization(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("exact steady start authorization is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(
        self,
    ) -> tuple[Mapping[str, object], Mapping[str, object]]:
        if self._state != "live":
            raise ExactSteadyStartAuthorizationError(
                "exact steady start authorization 已关闭"
            )
        plan, authorization = _derive_material(
            self._workspace,
            self._facts,
            self._closures,
            self._tooling,
            self._lineage,
            self._legacy_c_fence,
        )
        if (
            _identity.canonical_bytes(plan) != self._plan_raw
            or _identity.canonical_bytes(authorization)
            != self._authorization_raw
            or _identity.identity_sha256(authorization)
            != self._authorization_sha256
        ):
            raise ExactSteadyStartAuthorizationError(
                "exact steady start authorization live material 漂移"
            )
        return plan, authorization

    @property
    def scope(self) -> str:
        self._assert_live()
        return _AUTHORIZATION_SCOPE

    @property
    def authority_kind(self) -> str:
        return str(self._assert_live()[1]["authority_kind"])

    @property
    def runtime_state_kind(self) -> str:
        return str(self._assert_live()[1]["runtime_state_kind"])

    @property
    def boot_nonce(self) -> str:
        return str(self._assert_live()[1]["boot_nonce"])

    @property
    def state_identity_sha256(self) -> str:
        return str(self._assert_live()[1]["state_identity_sha256"])

    @property
    def scm_identity_sha256(self) -> str:
        return str(self._assert_live()[1]["scm_identity_sha256"])

    @property
    def authorization_sha256(self) -> str:
        self._assert_live()
        return self._authorization_sha256

    @property
    def release_ref(self) -> Mapping[str, object]:
        release = _clone(self._assert_live()[1]["release"])
        if type(release) is not dict:
            raise ExactSteadyStartAuthorizationError("steady release clone 漂移")
        return release

    @property
    def service_name(self) -> str:
        return str(self._assert_live()[0]["service"]["service_name"])

    @property
    def service_start_arguments(self) -> tuple[str, ...]:
        return tuple(
            str(value)
            for value in self._assert_live()[0]["service"]["start_arguments"]
        )

    @property
    def child_argv(self) -> tuple[str, ...]:
        return tuple(
            str(value) for value in self._assert_live()[0]["child"]["argv"]
        )

    def close(self) -> None:
        if self._state == "closed":
            return
        self._workspace._close_steady_start_authorization_public(self)  # noqa: SLF001

    def _close_from_workspace(self, workspace: LockedSteadyBootWorkspace) -> None:
        if workspace is not self._workspace:
            raise ExactSteadyStartAuthorizationError(
                "steady start authorization close owner 漂移"
            )
        object.__setattr__(self, "_state", "closed")
        workspace._release_steady_start_authorization(self)  # noqa: SLF001

    def __enter__(self) -> "LockedExactSteadyStartAuthorization":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedExactSteadyScmProcessObservationInput:
    """Exact steady authorization 与 active release closure 的只读 join。"""

    __slots__ = (
        "_workspace",
        "_authorization",
        "_closures",
        "_plan_raw",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact steady SCM/process observation input 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact steady SCM/process observation input 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        workspace: LockedSteadyBootWorkspace,
        authorization: LockedExactSteadyStartAuthorization,
        closures: LockedSteadyReleaseClosures,
        *,
        token: object,
    ) -> None:
        if (
            token is not _SCM_INPUT_TOKEN
            or type(workspace) is not LockedSteadyBootWorkspace
            or type(authorization) is not LockedExactSteadyStartAuthorization
            or type(closures) is not LockedSteadyReleaseClosures
            or authorization._workspace is not workspace  # noqa: SLF001
            or authorization._closures is not closures  # noqa: SLF001
            or closures._workspace is not workspace  # noqa: SLF001
        ):
            raise TypeError("exact steady SCM/process input provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._workspace = workspace
        self._authorization = authorization
        self._closures = closures
        plan, _authorization = authorization._assert_live()  # noqa: SLF001
        metadata = closures.metadata()
        roles = metadata["roles"]
        if (
            not isinstance(roles, Mapping)
            or not isinstance(roles.get("active"), Mapping)
            or roles["active"].get("release_id")
            != plan["release"]["release_id"]
            or roles["active"].get("manifest_sha256")
            != plan["release"]["manifest_sha256"]
        ):
            raise ExactSteadyStartAuthorizationError(
                "steady SCM input active release 不属于 exact closure"
            )
        self._plan_raw = _identity.canonical_bytes(plan)
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("exact steady SCM/process observation input is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_process_local_live(self) -> Mapping[str, object]:
        if (
            self._authorization._workspace is not self._workspace  # noqa: SLF001
            or self._authorization._closures is not self._closures  # noqa: SLF001
            or self._closures._workspace is not self._workspace  # noqa: SLF001
            or self._authorization._state != "live"  # noqa: SLF001
            or self._closures._engine._state != "live"  # noqa: SLF001
            or self._closures
            not in self._workspace._steady_release_closures  # noqa: SLF001
        ):
            raise DeploymentLockBusy("steady SCM input live chain provenance 漂移")
        self._workspace._assert_live()  # noqa: SLF001
        try:
            plan = json.loads(self._plan_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExactSteadyStartAuthorizationError(
                "steady SCM observation sealed plan 损坏"
            ) from error
        if type(plan) is not dict:
            raise ExactSteadyStartAuthorizationError(
                "steady SCM observation sealed plan 类型漂移"
            )
        return plan

    def _assert_live(self) -> Mapping[str, object]:
        local_plan = self._assert_process_local_live()
        plan, _authorization = self._authorization._assert_live()  # noqa: SLF001
        self._closures._assert_live()  # noqa: SLF001
        if (
            _identity.canonical_bytes(local_plan) != self._plan_raw
            or _identity.canonical_bytes(plan) != self._plan_raw
        ):
            raise ExactSteadyStartAuthorizationError(
                "steady SCM observation plan 漂移"
            )
        return plan

    def _observation_checkpoint_plan(self) -> Mapping[str, object]:
        plan = _clone(self._assert_live())
        if type(plan) is not dict:
            raise ExactSteadyStartAuthorizationError(
                "steady SCM observation checkpoint plan 类型漂移"
            )
        return plan

    def _observation_checkpoint_material(self) -> Mapping[str, object]:
        plan = self._observation_checkpoint_plan()
        material = dict(plan)
        material["authorization_sha256"] = (
            self._authorization._authorization_sha256  # noqa: SLF001
        )
        material["scm_identity_sha256"] = _identity.identity_sha256(plan)
        return material

    @property
    def scope(self) -> str:
        self._assert_live()
        return _SCM_INPUT_SCOPE

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
    def tooling_sha256(self) -> str:
        return str(self._assert_live()["tooling_sha256"])

    @property
    def receipt_lineage_aggregate_sha256(self) -> str:
        return str(self._assert_live()["receipt_lineage_aggregate_sha256"])

    @property
    def legacy_c_live_fence_aggregate_sha256(self) -> str:
        return str(
            self._assert_live()["legacy_c_live_fence_aggregate_sha256"]
        )

    @property
    def authorization_sha256(self) -> str:
        self._assert_live()
        return self._authorization.authorization_sha256

    @property
    def scm_identity_sha256(self) -> str:
        plan = self._assert_live()
        return _identity.identity_sha256(plan)

    @property
    def release_ref(self) -> Mapping[str, object]:
        release = _clone(self._assert_live()["release"])
        if type(release) is not dict:
            raise ExactSteadyStartAuthorizationError("steady SCM release clone 漂移")
        return release

    @property
    def service_name(self) -> str:
        return str(self._assert_live()["service"]["service_name"])

    @property
    def service_executable(self) -> str:
        return str(self._assert_live()["service"]["binary_path"])

    @property
    def python_class(self) -> str:
        return str(self._assert_live()["service"]["python_class"])

    @property
    def service_start_arguments(self) -> tuple[str, ...]:
        return tuple(
            str(value)
            for value in self._assert_live()["service"]["start_arguments"]
        )

    @property
    def child_executable(self) -> str:
        return str(self._assert_live()["child"]["executable"])

    @property
    def child_argv(self) -> tuple[str, ...]:
        return tuple(
            str(value) for value in self._assert_live()["child"]["argv"]
        )


class ProductionExactSteadyStartAuthorizer:
    __slots__ = ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production exact steady start authorizer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production exact steady start authorizer 不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _AUTHORIZER_TOKEN:
            raise TypeError("production exact steady start authorizer provenance 无效")
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production exact steady start authorizer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionExactSteadyStartAuthorizer":
        return cls(token=_AUTHORIZER_TOKEN)

    def authorize(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        lineage: LockedSteadyReceiptLineage,
        legacy_c_fence: LockedSteadyLegacyCPrelaunchFence,
    ) -> LockedExactSteadyStartAuthorization:
        if facts._persistence._test_only:  # noqa: SLF001
            raise DeploymentLockBusy("product steady authorizer 不接受 test-only root")
        return _authorize(
            workspace, facts, closures, tooling, lineage, legacy_c_fence
        )

    def bind_scm_process_observation_input(
        self,
        workspace: LockedSteadyBootWorkspace,
        authorization: LockedExactSteadyStartAuthorization,
        closures: LockedSteadyReleaseClosures,
    ) -> LockedExactSteadyScmProcessObservationInput:
        if authorization._facts._persistence._test_only:  # noqa: SLF001
            raise DeploymentLockBusy("product steady SCM input 不接受 test-only root")
        return _bind_scm_input(workspace, authorization, closures)


class _TestOnlyExactSteadyStartAuthorizerAdapter:
    __slots__ = ()

    @classmethod
    def for_test_only(cls) -> "_TestOnlyExactSteadyStartAuthorizerAdapter":
        return cls()

    def authorize_test_only(
        self,
        workspace: LockedSteadyBootWorkspace,
        facts: LockedSteadyPairStaticFacts,
        closures: LockedSteadyReleaseClosures,
        tooling: LockedSteadyExactRuntimeControllerToolingObservation,
        lineage: LockedSteadyReceiptLineage,
        legacy_c_fence: LockedSteadyLegacyCPrelaunchFence,
    ) -> LockedExactSteadyStartAuthorization:
        if not facts._persistence._test_only:  # noqa: SLF001
            raise DeploymentLockBusy("test steady authorizer 只接受 test-only root")
        return _authorize(
            workspace, facts, closures, tooling, lineage, legacy_c_fence
        )

    def bind_scm_process_observation_input_test_only(
        self,
        workspace: LockedSteadyBootWorkspace,
        authorization: LockedExactSteadyStartAuthorization,
        closures: LockedSteadyReleaseClosures,
    ) -> LockedExactSteadyScmProcessObservationInput:
        if not authorization._facts._persistence._test_only:  # noqa: SLF001
            raise DeploymentLockBusy("test steady SCM input 只接受 test-only root")
        return _bind_scm_input(workspace, authorization, closures)


def _authorize(
    workspace: LockedSteadyBootWorkspace,
    facts: LockedSteadyPairStaticFacts,
    closures: LockedSteadyReleaseClosures,
    tooling: LockedSteadyExactRuntimeControllerToolingObservation,
    lineage: LockedSteadyReceiptLineage,
    legacy_c_fence: LockedSteadyLegacyCPrelaunchFence,
) -> LockedExactSteadyStartAuthorization:
    authorization = LockedExactSteadyStartAuthorization(
        workspace,
        facts,
        closures,
        tooling,
        lineage,
        legacy_c_fence,
        token=_AUTHORIZATION_TOKEN,
    )
    authorization._assert_live()  # noqa: SLF001
    return authorization


def _bind_scm_input(
    workspace: LockedSteadyBootWorkspace,
    authorization: LockedExactSteadyStartAuthorization,
    closures: LockedSteadyReleaseClosures,
) -> LockedExactSteadyScmProcessObservationInput:
    bound = LockedExactSteadyScmProcessObservationInput(
        workspace,
        authorization,
        closures,
        token=_SCM_INPUT_TOKEN,
    )
    bound._assert_live()  # noqa: SLF001
    return bound


__all__ = [
    "ExactSteadyStartAuthorizationError",
    "LockedExactSteadyStartAuthorization",
    "LockedExactSteadyScmProcessObservationInput",
    "ProductionExactSteadyStartAuthorizer",
]
