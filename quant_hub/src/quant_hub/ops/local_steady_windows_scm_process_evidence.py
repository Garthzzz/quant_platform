"""Steady active Windows SCM／host／child 的 v2 closed evidence 合同。"""

from __future__ import annotations

from dataclasses import dataclass
import json

from .local_release_identity import canonical_bytes, identity_sha256
from .local_steady_start_authorization import (
    ExactSteadyStartAuthorizationError,
    LockedExactSteadyScmProcessObservationInput,
)
from .local_windows_scm_process_evidence import (
    WindowsScmProcessEvidenceError,
    _clone,
    _closed,
    _identifier,
    _process,
    _release_ref,
    _service,
    _sha256,
    _topology,
    _verify_self_hash,
)
from .local_deployment_persistence import DeploymentLockBusy, UnsafeLocalPath


STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA = (
    "qrh-windows-scm-process-observation/v2"
)
STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE = (
    "steady_scm_process_identity_observation_only"
)


def validate_steady_windows_scm_process_observation(
    value: object,
    inputs: LockedExactSteadyScmProcessObservationInput,
) -> dict[str, object]:
    """验证 exact steady tagged evidence；返回值仍不形成 writer 资格。"""

    if type(inputs) is not LockedExactSteadyScmProcessObservationInput:
        raise WindowsScmProcessEvidenceError(
            "steady SCM/process evidence 必须绑定 exact steady live input"
    )
    try:
        material = inputs._observation_checkpoint_material()  # noqa: SLF001
        service = material["service"]
        child = material["child"]
        if type(service) is not dict or type(child) is not dict:
            raise WindowsScmProcessEvidenceError(
                "steady SCM checkpoint plan service/child 类型漂移"
            )
        expected = {
            "authority_kind": material["authority_kind"],
            "runtime_state_kind": material["runtime_state_kind"],
            "boot_nonce": material["boot_nonce"],
            "active_release_sha256": material["active_release_sha256"],
            "binding_sha256": material["binding_sha256"],
            "retention_aggregate_sha256": material[
                "retention_aggregate_sha256"
            ],
            "state_identity_sha256": material["state_identity_sha256"],
            "tooling_sha256": material["tooling_sha256"],
            "receipt_lineage_aggregate_sha256": (
                material["receipt_lineage_aggregate_sha256"]
            ),
            "legacy_c_live_fence_aggregate_sha256": (
                material["legacy_c_live_fence_aggregate_sha256"]
            ),
            "authorization_sha256": material["authorization_sha256"],
            "scm_identity_sha256": material["scm_identity_sha256"],
            "release": material["release"],
            "service_name": service["service_name"],
            "service_executable": service["binary_path"],
            "python_class": service["python_class"],
            "child_executable": child["executable"],
            "child_argv": list(child["argv"]),
        }
    except (
        AttributeError,
        DeploymentLockBusy,
        ExactSteadyStartAuthorizationError,
        UnsafeLocalPath,
    ) as error:
        raise WindowsScmProcessEvidenceError(
            "steady SCM/process input 已撤销或不再 live"
        ) from error
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_scope",
            "authority_kind",
            "runtime_state_kind",
            "boot_nonce",
            "active_release_sha256",
            "binding_sha256",
            "retention_aggregate_sha256",
            "state_identity_sha256",
            "tooling_sha256",
            "receipt_lineage_aggregate_sha256",
            "legacy_c_live_fence_aggregate_sha256",
            "authorization_sha256",
            "scm_identity_sha256",
            "release",
            "service",
            "host",
            "child",
            "direct_child_topology",
            "observation_aggregate_sha256",
            "result",
            "evidence_sha256",
        },
        label="steady Windows SCM/process observation",
    )
    if (
        evidence["schema_version"]
        != STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA
        or evidence["evidence_scope"]
        != STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE
        or evidence["authority_kind"] != "steady_active"
        or evidence["runtime_state_kind"] != "steady_current"
    ):
        raise WindowsScmProcessEvidenceError(
            "steady SCM/process v2 tagged identity 不匹配"
        )
    _identifier(evidence["boot_nonce"], label="boot_nonce")
    for field in (
        "active_release_sha256",
        "binding_sha256",
        "retention_aggregate_sha256",
        "state_identity_sha256",
        "tooling_sha256",
        "receipt_lineage_aggregate_sha256",
        "legacy_c_live_fence_aggregate_sha256",
        "authorization_sha256",
        "scm_identity_sha256",
    ):
        _sha256(evidence[field], label=field)
    for field in (
        "authority_kind",
        "runtime_state_kind",
        "boot_nonce",
        "active_release_sha256",
        "binding_sha256",
        "retention_aggregate_sha256",
        "state_identity_sha256",
        "tooling_sha256",
        "receipt_lineage_aggregate_sha256",
        "legacy_c_live_fence_aggregate_sha256",
        "authorization_sha256",
        "scm_identity_sha256",
    ):
        if evidence[field] != expected[field]:
            raise WindowsScmProcessEvidenceError(
                f"steady SCM/process evidence.{field} 未绑定 live input"
            )
    release = _release_ref(evidence["release"])
    if release != expected["release"]:
        raise WindowsScmProcessEvidenceError(
            "steady SCM/process release 未绑定 active closure"
        )
    service = _service(
        evidence["service"],
        expected_name=str(expected["service_name"]),
        expected_executable=str(expected["service_executable"]),
        expected_python_class=str(expected["python_class"]),
    )
    status = service["status"]
    if type(status) is not dict:
        raise WindowsScmProcessEvidenceError("steady service.status 类型漂移")
    host_pid = int(status["process_id"])
    host = _process(
        evidence["host"],
        label="host",
        expected_parent_pid=None,
        expected_executable=str(expected["service_executable"]),
        expected_argv=[str(expected["service_executable"])],
    )
    if host["pid"] != host_pid or host["parent_pid"] == host_pid:
        raise WindowsScmProcessEvidenceError("steady SCM host PID 拓扑不闭合")
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
        or child["volume_identity_sha256"]
        != host["volume_identity_sha256"]
        or child["file_identity_sha256"] == host["file_identity_sha256"]
    ):
        raise WindowsScmProcessEvidenceError(
            "steady host/child time 或 executable identity 不闭合"
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
    if (
        evidence["observation_aggregate_sha256"] != aggregate
        or evidence["result"]
        != "steady_identity_observed_not_writer_qualified"
    ):
        raise WindowsScmProcessEvidenceError(
            "steady SCM/process aggregate 或 observation-only result 不匹配"
        )
    _verify_self_hash(
        evidence,
        field="evidence_sha256",
        label="steady Windows SCM/process observation",
    )
    return _clone(evidence, label="steady Windows SCM/process observation")


@dataclass(frozen=True, slots=True)
class SteadyWindowsScmProcessObservationEvidence:
    """可持久化的 steady observation；不是 process-local authority。"""

    _raw: bytes

    @classmethod
    def from_document(
        cls,
        value: object,
        inputs: LockedExactSteadyScmProcessObservationInput,
    ) -> "SteadyWindowsScmProcessObservationEvidence":
        validated = validate_steady_windows_scm_process_observation(
            value, inputs
        )
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsScmProcessEvidenceError(
                "已验证 steady observation 类型漂移"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA",
    "STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE",
    "SteadyWindowsScmProcessObservationEvidence",
    "validate_steady_windows_scm_process_observation",
]
