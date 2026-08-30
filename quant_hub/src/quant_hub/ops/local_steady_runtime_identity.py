"""Service-host 可重建的 exact steady runtime closed identity。

该对象只封闭无参 SCM steady start arguments 与固定 child argv；它不是 B2 live
authorization、Job authority、writer qualification 或 admission authority。
"""

from __future__ import annotations

import json
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_NONCE_192_RE = re.compile(r"^[0-9a-f]{48}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ARGUMENT_FLAGS = (
    "--authority-kind",
    "--runtime-state-kind",
    "--boot-nonce",
    "--active-release-sha256",
    "--binding-sha256",
    "--retention-aggregate-sha256",
    "--state-identity-sha256",
    "--release-id",
    "--manifest-sha256",
    "--tooling-sha256",
    "--receipt-lineage-aggregate-sha256",
    "--legacy-c-live-fence-aggregate-sha256",
)
_ARGUMENT_FIELDS = (
    "authority_kind",
    "runtime_state_kind",
    "boot_nonce",
    "active_release_sha256",
    "binding_sha256",
    "retention_aggregate_sha256",
    "state_identity_sha256",
    "release_id",
    "manifest_sha256",
    "tooling_sha256",
    "receipt_lineage_aggregate_sha256",
    "legacy_c_live_fence_aggregate_sha256",
)
_PRODUCTION_ROOT = r"D:\quant\quant_platform"
_SERVICE_NAME = "QuantResearchHub"
_SCM_HOST_EXECUTABLE = (
    _PRODUCTION_ROOT
    + r"\tooling\python\Lib\site-packages\win32\pythonservice.exe"
)
_SCM_PYTHON_CLASS = "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
_CHILD_EXECUTABLE = _PRODUCTION_ROOT + r"\tooling\python\python.exe"
_CHILD_MODULE = "quant_hub.ops.local_exact_runtime_entry"
_PYCACHE_PARENT = _PRODUCTION_ROOT + r"\tmp\service\pycache"


class ExactSteadyRuntimeIdentityError(RuntimeError):
    """SCM steady arguments 不能形成唯一 closed runtime identity。"""


def _parse_exact_steady_argv(values: object) -> dict[str, str]:
    """解析 child 的固定 steady argv 尾部；拒绝 mapping、别名和重排。"""

    if type(values) is not tuple or len(values) != 2 * len(_ARGUMENT_FLAGS):
        raise ExactSteadyRuntimeIdentityError("steady runtime argv length is not closed")
    parsed: dict[str, str] = {}
    for index, (flag, field) in enumerate(
        zip(_ARGUMENT_FLAGS, _ARGUMENT_FIELDS, strict=True)
    ):
        observed_flag = values[index * 2]
        observed_value = values[index * 2 + 1]
        if (
            observed_flag != flag
            or type(observed_value) is not str
            or not observed_value
        ):
            raise ExactSteadyRuntimeIdentityError(
                f"steady runtime argv differs at {flag}"
            )
        parsed[field] = observed_value
    return parsed


class ExactSteadyRuntimeIdentity:
    """固定 steady SCM args 的不可变 closed identity；不承载 live capability。"""

    __slots__ = tuple("_" + field for field in _ARGUMENT_FIELDS) + ("_sealed",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact steady runtime identity 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact steady runtime identity 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        authority_kind: str,
        runtime_state_kind: str,
        boot_nonce: str,
        active_release_sha256: str,
        binding_sha256: str,
        retention_aggregate_sha256: str,
        state_identity_sha256: str,
        release_id: str,
        manifest_sha256: str,
        tooling_sha256: str,
        receipt_lineage_aggregate_sha256: str,
        legacy_c_live_fence_aggregate_sha256: str,
    ) -> None:
        object.__setattr__(self, "_sealed", False)
        values = {
            "authority_kind": authority_kind,
            "runtime_state_kind": runtime_state_kind,
            "boot_nonce": boot_nonce,
            "active_release_sha256": active_release_sha256,
            "binding_sha256": binding_sha256,
            "retention_aggregate_sha256": retention_aggregate_sha256,
            "state_identity_sha256": state_identity_sha256,
            "release_id": release_id,
            "manifest_sha256": manifest_sha256,
            "tooling_sha256": tooling_sha256,
            "receipt_lineage_aggregate_sha256": receipt_lineage_aggregate_sha256,
            "legacy_c_live_fence_aggregate_sha256": (
                legacy_c_live_fence_aggregate_sha256
            ),
        }
        if authority_kind != "steady_active":
            raise ExactSteadyRuntimeIdentityError("steady authority_kind 不匹配")
        if runtime_state_kind != "steady_current":
            raise ExactSteadyRuntimeIdentityError("steady runtime_state_kind 不匹配")
        if type(boot_nonce) is not str or _NONCE_192_RE.fullmatch(boot_nonce) is None:
            raise ExactSteadyRuntimeIdentityError("steady boot_nonce 无效")
        if type(release_id) is not str or _IDENTIFIER_RE.fullmatch(release_id) is None:
            raise ExactSteadyRuntimeIdentityError("steady release_id 无效")
        for field in (
            "active_release_sha256",
            "binding_sha256",
            "retention_aggregate_sha256",
            "state_identity_sha256",
            "manifest_sha256",
            "tooling_sha256",
            "receipt_lineage_aggregate_sha256",
            "legacy_c_live_fence_aggregate_sha256",
        ):
            value = values[field]
            if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
                raise ExactSteadyRuntimeIdentityError(
                    f"steady identity.{field} 无效"
                )
        for field, value in values.items():
            object.__setattr__(self, "_" + field, value)
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("exact steady runtime identity is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _values(self) -> dict[str, str]:
        return {field: str(getattr(self, "_" + field)) for field in _ARGUMENT_FIELDS}

    @property
    def boot_nonce(self) -> str:
        return self._boot_nonce

    @property
    def state_identity_sha256(self) -> str:
        return self._state_identity_sha256

    @property
    def active_release_sha256(self) -> str:
        return self._active_release_sha256

    @property
    def binding_sha256(self) -> str:
        return self._binding_sha256

    @property
    def retention_aggregate_sha256(self) -> str:
        return self._retention_aggregate_sha256

    @property
    def tooling_sha256(self) -> str:
        return self._tooling_sha256

    @property
    def receipt_lineage_aggregate_sha256(self) -> str:
        return self._receipt_lineage_aggregate_sha256

    @property
    def legacy_c_live_fence_aggregate_sha256(self) -> str:
        return self._legacy_c_live_fence_aggregate_sha256

    @property
    def release_id(self) -> str:
        return self._release_id

    @property
    def manifest_sha256(self) -> str:
        return self._manifest_sha256

    @property
    def release_path(self) -> str:
        return _PRODUCTION_ROOT + "\\releases\\" + self._release_id

    @property
    def pycache_prefix(self) -> str:
        return _PYCACHE_PARENT + "\\" + self._boot_nonce

    @property
    def runtime_arguments(self) -> tuple[str, ...]:
        values = self._values()
        return tuple(
            item
            for flag, field in zip(_ARGUMENT_FLAGS, _ARGUMENT_FIELDS, strict=True)
            for item in (flag, values[field])
        )

    @property
    def service_start_arguments(self) -> tuple[str, ...]:
        return ("steady-exact-runtime", *self.runtime_arguments)

    @property
    def child_argv(self) -> tuple[str, ...]:
        return (
            _CHILD_EXECUTABLE,
            "-I",
            "-B",
            "-X",
            "utf8",
            "-X",
            "pycache_prefix=" + self.pycache_prefix,
            "-m",
            _CHILD_MODULE,
            *self.runtime_arguments,
        )

    @property
    def release_ref(self) -> Mapping[str, object]:
        return {
            "release_id": self._release_id,
            "release_path": self.release_path,
            "manifest_sha256": self._manifest_sha256,
        }

    @property
    def scm_plan_document(self) -> Mapping[str, object]:
        plan: dict[str, object] = {
            "schema_version": "qrh-exact-steady-scm-start-plan/v1",
            "scope": "exact_steady_scm_start_plan_input_only",
            "authority_kind": self._authority_kind,
            "runtime_state_kind": self._runtime_state_kind,
            "boot_nonce": self._boot_nonce,
            "active_release_sha256": self._active_release_sha256,
            "binding_sha256": self._binding_sha256,
            "retention_aggregate_sha256": self._retention_aggregate_sha256,
            "state_identity_sha256": self._state_identity_sha256,
            "release": dict(self.release_ref),
            "tooling_sha256": self._tooling_sha256,
            "receipt_lineage_aggregate_sha256": (
                self._receipt_lineage_aggregate_sha256
            ),
            "legacy_c_live_fence_aggregate_sha256": (
                self._legacy_c_live_fence_aggregate_sha256
            ),
            "service": {
                "service_name": _SERVICE_NAME,
                "binary_path": _SCM_HOST_EXECUTABLE,
                "python_class": _SCM_PYTHON_CLASS,
                "start_type": "automatic",
                "start_arguments": list(self.service_start_arguments),
            },
            "child": {
                "executable": _CHILD_EXECUTABLE,
                "module": _CHILD_MODULE,
                "argv": list(self.child_argv),
            },
        }
        return json.loads(canonical_bytes(plan).decode("utf-8"))

    @property
    def scm_identity_sha256(self) -> str:
        return identity_sha256(self.scm_plan_document)

    @property
    def authorization_document(self) -> Mapping[str, object]:
        document: dict[str, object] = {
            "schema_version": "qrh-exact-steady-start-authorization/v1",
            "scope": "exact_steady_start_authorization_input_only",
            "authority_kind": self._authority_kind,
            "runtime_state_kind": self._runtime_state_kind,
            "boot_nonce": self._boot_nonce,
            "active_release_sha256": self._active_release_sha256,
            "binding_sha256": self._binding_sha256,
            "retention_aggregate_sha256": self._retention_aggregate_sha256,
            "state_identity_sha256": self._state_identity_sha256,
            "release": dict(self.release_ref),
            "tooling_sha256": self._tooling_sha256,
            "receipt_lineage_aggregate_sha256": (
                self._receipt_lineage_aggregate_sha256
            ),
            "legacy_c_live_fence_aggregate_sha256": (
                self._legacy_c_live_fence_aggregate_sha256
            ),
            "scm_identity_sha256": self.scm_identity_sha256,
        }
        return json.loads(canonical_bytes(document).decode("utf-8"))

    @property
    def authorization_sha256(self) -> str:
        return identity_sha256(self.authorization_document)


__all__ = [
    "ExactSteadyRuntimeIdentity",
    "ExactSteadyRuntimeIdentityError",
]
