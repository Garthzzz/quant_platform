"""Windows SCM／host／child 进程观察的纯 closed-schema 合同。

本模块不调用 Windows API、不打开 handle、不启动服务，也不形成 writer lease 或部署
资格。文档必须绑定 live ``LockedExactScmProcessObservationInput``；即使验证通过，scope
也固定为 observation-only，后续 formal producer 仍必须消费不可反序列化的现场能力。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping

from .local_deployment_persistence import (
    DeploymentJournalError,
    DeploymentLockBusy,
    LockedExactScmProcessObservationInput,
    UnsafeLocalPath,
)
from .local_release_identity import (
    LocalReleaseIdentityError,
    canonical_bytes,
    identity_sha256,
)


WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA = (
    "qrh-windows-scm-process-observation/v1"
)
WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE = (
    "scm_process_identity_observation_only"
)

_OPERATIONS = {"activation", "rollback", "bootstrap_first_pair"}
_ROLES = {"prior", "candidate", "baseline"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_PRODUCTION_RELEASE_PREFIX = "D:\\quant\\quant_platform\\releases\\"


class WindowsScmProcessEvidenceError(RuntimeError):
    """SCM／process observation 不是 closed、canonical 或 exact-bound。"""


def _clone(value: object, *, label: str) -> dict[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except (
        LocalReleaseIdentityError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise WindowsScmProcessEvidenceError(
            f"{label} 不是 canonical JSON"
        ) from error
    if type(cloned) is not dict:
        raise WindowsScmProcessEvidenceError(f"{label} 必须是 JSON object")
    return cloned


def _closed(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise WindowsScmProcessEvidenceError(f"{label} schema 不闭合")
    return value


def _identifier(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _IDENTIFIER_RE.fullmatch(value) is None
        or value.endswith((".", " "))
    ):
        raise WindowsScmProcessEvidenceError(f"{label} identifier 无效")
    return value


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WindowsScmProcessEvidenceError(f"{label} SHA-256 无效")
    return value


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WindowsScmProcessEvidenceError(
            f"{label} 必须是 >= {minimum} 的整数"
        )
    return value


def _verify_self_hash(
    document: Mapping[str, object], *, field: str, label: str
) -> str:
    claimed = _sha256(document[field], label=f"{label}.{field}")
    material = dict(document)
    material.pop(field)
    if identity_sha256(material) != claimed:
        raise WindowsScmProcessEvidenceError(f"{label} self hash 不匹配")
    return claimed


def _release_ref(value: object) -> dict[str, object]:
    release = _closed(
        value,
        {"release_id", "release_path", "manifest_sha256"},
        label="release",
    )
    release_id = _identifier(release["release_id"], label="release_id")
    if release["release_path"] != _PRODUCTION_RELEASE_PREFIX + release_id:
        raise WindowsScmProcessEvidenceError(
            "release_path 不是 exact D release path"
        )
    _sha256(release["manifest_sha256"], label="release.manifest_sha256")
    return release


def _status(value: object) -> dict[str, object]:
    status = _closed(
        value,
        {
            "current_state",
            "controls_accepted",
            "win32_exit_code",
            "service_specific_exit_code",
            "checkpoint",
            "wait_hint_ms",
            "process_id",
            "service_flags",
        },
        label="service.status",
    )
    _integer(status["current_state"], label="current_state")
    if status["current_state"] != 4:
        raise WindowsScmProcessEvidenceError("SCM service 必须处于 SERVICE_RUNNING")
    _integer(status["controls_accepted"], label="controls_accepted")
    for field in (
        "win32_exit_code",
        "service_specific_exit_code",
        "checkpoint",
        "wait_hint_ms",
        "service_flags",
    ):
        _integer(status[field], label=f"service.status.{field}")
        if status[field] != 0:
            raise WindowsScmProcessEvidenceError(
                f"service.status.{field} 必须为 0"
            )
    _integer(status["process_id"], label="service process_id", minimum=1)
    return status


def _service(
    value: object,
    *,
    expected_name: str,
    expected_executable: str,
    expected_python_class: str,
) -> dict[str, object]:
    service = _closed(
        value,
        {
            "service_name",
            "service_type",
            "start_type",
            "error_control",
            "binary_path_argv",
            "service_start_name",
            "python_class",
            "status",
            "service_identity_sha256",
        },
        label="service",
    )
    for field in ("service_type", "start_type", "error_control"):
        _integer(service[field], label=f"service.{field}")
    if (
        service["service_name"] != expected_name
        or service["service_type"] != 16
        or service["start_type"] != 2
        or service["error_control"] != 1
        or service["binary_path_argv"] != [expected_executable]
        or service["service_start_name"] != "LocalSystem"
        or service["python_class"] != expected_python_class
    ):
        raise WindowsScmProcessEvidenceError(
            "SCM configuration 与 exact D start plan 不一致"
        )
    _status(service["status"])
    _verify_self_hash(
        service, field="service_identity_sha256", label="service observation"
    )
    return service


def _process(
    value: object,
    *,
    label: str,
    expected_parent_pid: int | None,
    expected_executable: str,
    expected_argv: list[str],
) -> dict[str, object]:
    process = _closed(
        value,
        {
            "pid",
            "parent_pid",
            "creation_time_100ns",
            "executable_final_path",
            "volume_identity_sha256",
            "file_identity_sha256",
            "argv",
            "process_identity_sha256",
        },
        label=label,
    )
    _integer(process["pid"], label=f"{label}.pid", minimum=1)
    _integer(process["parent_pid"], label=f"{label}.parent_pid", minimum=1)
    if (
        expected_parent_pid is not None
        and process["parent_pid"] != expected_parent_pid
    ):
        raise WindowsScmProcessEvidenceError(f"{label}.parent_pid 不匹配")
    _integer(
        process["creation_time_100ns"],
        label=f"{label}.creation_time_100ns",
        minimum=1,
    )
    if (
        process["executable_final_path"] != expected_executable
        or process["argv"] != expected_argv
    ):
        raise WindowsScmProcessEvidenceError(
            f"{label} executable/argv 与 exact plan 不一致"
        )
    _sha256(
        process["volume_identity_sha256"],
        label=f"{label}.volume_identity_sha256",
    )
    _sha256(
        process["file_identity_sha256"],
        label=f"{label}.file_identity_sha256",
    )
    _verify_self_hash(
        process, field="process_identity_sha256", label=f"{label} identity"
    )
    return process


def _topology(
    value: object, *, host_pid: int, child_pid: int
) -> dict[str, object]:
    topology = _closed(
        value,
        {
            "host_pid",
            "direct_child_pids",
            "topology_identity_sha256",
        },
        label="direct child topology",
    )
    _integer(topology["host_pid"], label="topology.host_pid", minimum=1)
    direct_child_pids = topology["direct_child_pids"]
    if type(direct_child_pids) is not list or len(direct_child_pids) != 1:
        raise WindowsScmProcessEvidenceError("direct child PID 枚举不闭合")
    _integer(
        direct_child_pids[0],
        label="topology.direct_child_pids[0]",
        minimum=1,
    )
    if topology["host_pid"] != host_pid or direct_child_pids != [child_pid]:
        raise WindowsScmProcessEvidenceError(
            "host 必须恰有一个、且只能是已观察 child 的直接子进程"
        )
    _verify_self_hash(
        topology,
        field="topology_identity_sha256",
        label="direct child topology",
    )
    return topology


def validate_windows_scm_process_observation(
    value: object,
    inputs: LockedExactScmProcessObservationInput,
) -> dict[str, object]:
    """验证 observation document；返回值仍不是 authority capability。"""

    if type(inputs) is not LockedExactScmProcessObservationInput:
        raise WindowsScmProcessEvidenceError(
            "SCM/process evidence 必须绑定 exact live input"
        )
    try:
        expected = {
            "attempt_id": inputs.attempt_id,
            "nonce": inputs.nonce,
            "operation": inputs.operation,
            "role": inputs.role,
            "start_nonce": inputs.start_nonce,
            "authorization_sha256": inputs.authorization_sha256,
            "scm_identity_sha256": inputs.scm_identity_sha256,
            "state_identity_sha256": inputs.state_identity_sha256,
            "release": inputs.release_ref,
            "service_name": inputs.service_name,
            "service_executable": inputs.service_executable,
            "python_class": inputs.python_class,
            "child_executable": inputs.child_executable,
            "child_argv": list(inputs.child_argv),
        }
    except (
        AttributeError,
        DeploymentJournalError,
        DeploymentLockBusy,
        UnsafeLocalPath,
    ) as error:
        raise WindowsScmProcessEvidenceError(
            "SCM/process evidence input 未初始化、已撤销或不再 live"
        ) from error
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_scope",
            "attempt_id",
            "nonce",
            "operation",
            "authorization_phase",
            "role",
            "start_nonce",
            "authorization_sha256",
            "scm_identity_sha256",
            "state_identity_sha256",
            "release",
            "service",
            "host",
            "child",
            "direct_child_topology",
            "observation_aggregate_sha256",
            "result",
            "evidence_sha256",
        },
        label="Windows SCM/process observation",
    )
    if evidence["schema_version"] != WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA:
        raise WindowsScmProcessEvidenceError("SCM/process schema_version 不同")
    if evidence["evidence_scope"] != WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE:
        raise WindowsScmProcessEvidenceError("SCM/process evidence 不得冒充资格")
    for field in ("attempt_id", "nonce"):
        _identifier(evidence[field], label=field)
    if evidence["operation"] not in _OPERATIONS:
        raise WindowsScmProcessEvidenceError("operation 不属于本地部署状态机")
    if evidence["role"] not in _ROLES:
        raise WindowsScmProcessEvidenceError("role 不属于 exact start role")
    authorization_phase = (
        "prior_start_authorized"
        if evidence["role"] == "prior"
        else "candidate_start_authorized"
    )
    if evidence["authorization_phase"] != authorization_phase:
        raise WindowsScmProcessEvidenceError("authorization_phase 与 role 不匹配")
    _identifier(evidence["start_nonce"], label="start_nonce")
    for field in (
        "authorization_sha256",
        "scm_identity_sha256",
        "state_identity_sha256",
    ):
        _sha256(evidence[field], label=field)
    release = _release_ref(evidence["release"])
    for field in (
        "attempt_id",
        "nonce",
        "operation",
        "role",
        "start_nonce",
        "authorization_sha256",
        "scm_identity_sha256",
        "state_identity_sha256",
    ):
        if evidence[field] != expected[field]:
            raise WindowsScmProcessEvidenceError(
                f"SCM/process evidence.{field} 未绑定 live input"
            )
    if release != expected["release"]:
        raise WindowsScmProcessEvidenceError(
            "SCM/process evidence release 未绑定 live input"
        )
    service = _service(
        evidence["service"],
        expected_name=str(expected["service_name"]),
        expected_executable=str(expected["service_executable"]),
        expected_python_class=str(expected["python_class"]),
    )
    status = service["status"]
    if type(status) is not dict:
        raise WindowsScmProcessEvidenceError("service.status 类型漂移")
    host_pid = int(status["process_id"])
    host = _process(
        evidence["host"],
        label="host",
        expected_parent_pid=None,
        expected_executable=str(expected["service_executable"]),
        expected_argv=[str(expected["service_executable"])],
    )
    if host["pid"] != host_pid:
        raise WindowsScmProcessEvidenceError(
            "host PID 未绑定 QueryServiceStatusEx process_id"
        )
    if host["parent_pid"] == host_pid:
        raise WindowsScmProcessEvidenceError("host parent PID 不得等于自身")
    child = _process(
        evidence["child"],
        label="child",
        expected_parent_pid=host_pid,
        expected_executable=str(expected["child_executable"]),
        expected_argv=expected["child_argv"],  # type: ignore[arg-type]
    )
    if (
        child["pid"] == host_pid
        or child["creation_time_100ns"] < host["creation_time_100ns"]
    ):
        raise WindowsScmProcessEvidenceError("child process topology/time 不闭合")
    if (
        child["volume_identity_sha256"]
        != host["volume_identity_sha256"]
        or child["file_identity_sha256"] == host["file_identity_sha256"]
    ):
        raise WindowsScmProcessEvidenceError(
            "host/child 固定 D executable 文件身份不一致"
        )
    topology = _topology(
        evidence["direct_child_topology"],
        host_pid=host_pid,
        child_pid=int(child["pid"]),
    )
    aggregate = identity_sha256(
        [
            {"name": "service", "sha256": service["service_identity_sha256"]},
            {"name": "host", "sha256": host["process_identity_sha256"]},
            {"name": "child", "sha256": child["process_identity_sha256"]},
            {
                "name": "direct_child_topology",
                "sha256": topology["topology_identity_sha256"],
            },
        ]
    )
    if evidence["observation_aggregate_sha256"] != aggregate:
        raise WindowsScmProcessEvidenceError("SCM/process aggregate hash 不匹配")
    if evidence["result"] != "identity_observed_not_writer_qualified":
        raise WindowsScmProcessEvidenceError("SCM/process result 不得冒充资格")
    _verify_self_hash(
        evidence, field="evidence_sha256", label="Windows SCM/process observation"
    )
    return _clone(evidence, label="Windows SCM/process observation")


@dataclass(frozen=True, slots=True)
class WindowsScmProcessObservationEvidence:
    """可持久化 observation；不是 process-local authority。"""

    _raw: bytes

    @classmethod
    def from_document(
        cls,
        value: object,
        inputs: LockedExactScmProcessObservationInput,
    ) -> "WindowsScmProcessObservationEvidence":
        validated = validate_windows_scm_process_observation(value, inputs)
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsScmProcessEvidenceError("已验证 observation 类型漂移")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA",
    "WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE",
    "WindowsScmProcessEvidenceError",
    "WindowsScmProcessObservationEvidence",
    "validate_windows_scm_process_observation",
]
