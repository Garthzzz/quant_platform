"""Windows 写者租约与 kernel 锁观察的纯持久 closed-schema 合同。

本模块不打开文件、不复制 handle、不访问 endpoint，也不形成 canary 或部署资格。
租约记录是 child claim；只有后续 process-local observer 以 ``DuplicateHandle`` 证明
该 handle 确实属于已观察 SCM child，并证明冲突 writer 仍被 kernel 拒绝后，才可生成
本模块验证的 observation-only 文档。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256
from .local_windows_endpoint_evidence import (
    WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
    WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
    WindowsEndpointObservationEvidence,
    validate_windows_endpoint_observation,
)
from .local_windows_scm_process_evidence import (
    WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    WindowsScmProcessObservationEvidence,
)


WRITER_LEASE_RECORD_SCHEMA = "qrh-local-writer-lease-record/v1"
WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA = (
    "qrh-windows-writer-lease-observation/v1"
)
WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE = "writer_lease_observation_only"

WRITER_LOCK_RELATIVE_PATH = "state/writer_authority.lock"
WRITER_LOCK_FINAL_PATH = (
    "D:\\quant\\quant_platform\\state\\writer_authority.lock"
)
WRITER_LEASE_RECORD_RELATIVE_PATH = "state/writer_lease.json"
WRITER_LEASE_RECORD_FINAL_PATH = (
    "D:\\quant\\quant_platform\\state\\writer_lease.json"
)

_OPERATIONS = {"activation", "rollback", "bootstrap_first_pair"}
_ROLES = {"prior", "candidate", "baseline"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_128_RE = re.compile(r"^[0-9a-f]{32}$")
_NONCE_192_RE = re.compile(r"^[0-9a-f]{48}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_RELEASE_PREFIX = "D:\\quant\\quant_platform\\releases\\"
_MAX_PERSISTED_HANDLE = (1 << 64) - 2
_ERROR_SHARING_VIOLATION = 32


class WindowsWriterLeaseEvidenceError(RuntimeError):
    """writer lease 文档不是 closed、canonical 或未绑定上游观察。"""


def _clone(value: object, *, label: str) -> dict[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except Exception as error:
        raise WindowsWriterLeaseEvidenceError(
            f"{label} 不是 canonical JSON"
        ) from error
    if type(cloned) is not dict:
        raise WindowsWriterLeaseEvidenceError(f"{label} 必须是 JSON object")
    return cloned


def _closed(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise WindowsWriterLeaseEvidenceError(f"{label} schema 不闭合")
    return value


def _identifier(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _IDENTIFIER_RE.fullmatch(value) is None
        or value.endswith((".", " "))
    ):
        raise WindowsWriterLeaseEvidenceError(f"{label} identifier 无效")
    return value


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WindowsWriterLeaseEvidenceError(f"{label} SHA-256 无效")
    return value


def _positive_integer(
    value: object,
    *,
    label: str,
    maximum: int | None = None,
) -> int:
    if (
        type(value) is not int
        or value < 1
        or (maximum is not None and value > maximum)
    ):
        raise WindowsWriterLeaseEvidenceError(f"{label} 正整数域无效")
    return value


def _self_hash(document: Mapping[str, object], field: str, *, label: str) -> str:
    claimed = _sha256(document[field], label=f"{label}.{field}")
    material = dict(document)
    material.pop(field)
    if identity_sha256(material) != claimed:
        raise WindowsWriterLeaseEvidenceError(f"{label} self hash 不匹配")
    return claimed


def _release(value: object) -> dict[str, object]:
    release = _closed(
        value,
        {"release_id", "release_path", "manifest_sha256"},
        label="release",
    )
    release_id = _identifier(release["release_id"], label="release_id")
    if release["release_path"] != _RELEASE_PREFIX + release_id:
        raise WindowsWriterLeaseEvidenceError(
            "release_path 不是 exact D release path"
        )
    _sha256(release["manifest_sha256"], label="release.manifest_sha256")
    return release


def _scm_document(
    evidence: WindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not WindowsScmProcessObservationEvidence:
        raise WindowsWriterLeaseEvidenceError(
            "writer lease 必须绑定 typed SCM/process evidence"
        )
    try:
        document = evidence.as_dict()
    except Exception as error:
        raise WindowsWriterLeaseEvidenceError(
            "SCM/process evidence 不可读取"
        ) from error
    required = {
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
    }
    _closed(document, required, label="SCM/process observation")
    if (
        document["schema_version"] != WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA
        or document["evidence_scope"] != WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE
        or document["result"] != "identity_observed_not_writer_qualified"
    ):
        raise WindowsWriterLeaseEvidenceError(
            "SCM/process evidence 权限边界不同"
        )
    _self_hash(document, "evidence_sha256", label="SCM/process observation")
    return document


def _endpoint_document(
    evidence: WindowsEndpointObservationEvidence,
    scm_evidence: WindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not WindowsEndpointObservationEvidence:
        raise WindowsWriterLeaseEvidenceError(
            "writer lease 必须绑定 typed endpoint evidence"
        )
    try:
        document = validate_windows_endpoint_observation(
            evidence.as_dict(), scm_evidence
        )
    except Exception as error:
        raise WindowsWriterLeaseEvidenceError(
            "endpoint evidence 未绑定同一 SCM/process evidence"
        ) from error
    if (
        document["schema_version"] != WINDOWS_ENDPOINT_OBSERVATION_SCHEMA
        or document["evidence_scope"] != WINDOWS_ENDPOINT_OBSERVATION_SCOPE
        or document["result"] != "endpoint_observed_not_writer_qualified"
    ):
        raise WindowsWriterLeaseEvidenceError("endpoint evidence 权限边界不同")
    return document


def _identity_from_scm(document: Mapping[str, object]) -> dict[str, object]:
    service = document.get("service")
    host = document.get("host")
    child = document.get("child")
    if not all(type(value) is dict for value in (service, host, child)):
        raise WindowsWriterLeaseEvidenceError("SCM process identity 结构无效")
    identity: dict[str, object] = {
        "attempt_id": document["attempt_id"],
        "nonce": document["nonce"],
        "operation": document["operation"],
        "role": document["role"],
        "start_nonce": document["start_nonce"],
        "authorization_sha256": document["authorization_sha256"],
        "scm_identity_sha256": document["scm_identity_sha256"],
        "state_identity_sha256": document["state_identity_sha256"],
        "release": document["release"],
        "service_name": service.get("service_name"),  # type: ignore[union-attr]
        "host_pid": host.get("pid"),  # type: ignore[union-attr]
        "host_creation_time_100ns": host.get("creation_time_100ns"),  # type: ignore[union-attr]
        "child_pid": child.get("pid"),  # type: ignore[union-attr]
        "child_creation_time_100ns": child.get("creation_time_100ns"),  # type: ignore[union-attr]
    }
    for field in (
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
    ):
        _positive_integer(identity[field], label=f"SCM.{field}")
    if identity["service_name"] != "QuantResearchHub":
        raise WindowsWriterLeaseEvidenceError("SCM service_name 漂移")
    return identity


def _endpoint_lease_claim(document: Mapping[str, object]) -> dict[str, object]:
    probe = document.get("probe")
    if type(probe) is not dict:
        raise WindowsWriterLeaseEvidenceError("endpoint probe 结构无效")
    response = probe.get("response")
    if type(response) is not dict:
        raise WindowsWriterLeaseEvidenceError("endpoint response 结构无效")
    claim = response.get("writer_lease")
    return _closed(
        claim,
        {
            "lease_id",
            "lease_nonce",
            "lease_epoch",
            "lease_record_sha256",
            "authority",
        },
        label="endpoint writer lease claim",
    )


def _holder(value: object, *, expected: Mapping[str, object]) -> dict[str, object]:
    holder = _closed(
        value,
        {
            "service_name",
            "host_pid",
            "host_creation_time_100ns",
            "child_pid",
            "child_creation_time_100ns",
            "holder_identity_sha256",
        },
        label="writer lease holder",
    )
    for field in (
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
    ):
        _positive_integer(holder[field], label=f"writer lease holder.{field}")
    if any(
        holder[field] != expected[field]
        for field in (
            "service_name",
            "host_pid",
            "host_creation_time_100ns",
            "child_pid",
            "child_creation_time_100ns",
        )
    ):
        raise WindowsWriterLeaseEvidenceError(
            "writer lease holder 未绑定 SCM process identity"
        )
    _self_hash(holder, "holder_identity_sha256", label="writer lease holder")
    return holder


def _lock_claim(value: object) -> dict[str, object]:
    lock = _closed(
        value,
        {
            "relative_path",
            "final_path",
            "handle_value",
            "volume_serial_number",
            "file_id",
            "desired_access",
            "share_mode",
            "creation_disposition",
            "lock_identity_sha256",
        },
        label="writer kernel lock claim",
    )
    _positive_integer(
        lock["handle_value"],
        label="writer kernel lock claim.handle_value",
        maximum=_MAX_PERSISTED_HANDLE,
    )
    _positive_integer(
        lock["volume_serial_number"],
        label="writer kernel lock claim.volume_serial_number",
        maximum=(1 << 64) - 1,
    )
    if type(lock["file_id"]) is not str or _HEX_128_RE.fullmatch(lock["file_id"]) is None:
        raise WindowsWriterLeaseEvidenceError("writer kernel lock file_id 无效")
    if (
        lock["relative_path"] != WRITER_LOCK_RELATIVE_PATH
        or lock["final_path"] != WRITER_LOCK_FINAL_PATH
        or lock["desired_access"] != "GENERIC_READ|GENERIC_WRITE"
        or lock["share_mode"] != "FILE_SHARE_READ"
        or lock["creation_disposition"] != "OPEN_ALWAYS"
    ):
        raise WindowsWriterLeaseEvidenceError("writer kernel lock claim 不是固定 D 合同")
    _self_hash(lock, "lock_identity_sha256", label="writer kernel lock claim")
    return lock


def _expected_lease_id(record: Mapping[str, object]) -> str:
    return "lease-" + identity_sha256(
        {
            "attempt_id": record["attempt_id"],
            "nonce": record["nonce"],
            "role": record["role"],
            "start_nonce": record["start_nonce"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
        }
    )[:32]


def validate_writer_lease_record(
    value: object,
    scm_evidence: WindowsScmProcessObservationEvidence,
    endpoint_evidence: WindowsEndpointObservationEvidence,
) -> dict[str, object]:
    """验证 child 发布的租约记录；返回值仍只是持久 claim。"""

    scm = _scm_document(scm_evidence)
    endpoint = _endpoint_document(endpoint_evidence, scm_evidence)
    expected = _identity_from_scm(scm)
    claim = _endpoint_lease_claim(endpoint)
    record = _closed(
        value,
        {
            "schema_version",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "start_nonce",
            "authorization_sha256",
            "scm_identity_sha256",
            "state_identity_sha256",
            "release",
            "lease_id",
            "lease_nonce",
            "lease_epoch",
            "holder",
            "lock",
            "lease_record_sha256",
        },
        label="writer lease record",
    )
    if record["schema_version"] != WRITER_LEASE_RECORD_SCHEMA:
        raise WindowsWriterLeaseEvidenceError("writer lease record schema 不匹配")
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
        if record[field] != expected[field]:
            raise WindowsWriterLeaseEvidenceError(
                f"writer lease record.{field} 未绑定 SCM observation"
            )
    if record["operation"] not in _OPERATIONS or record["role"] not in _ROLES:
        raise WindowsWriterLeaseEvidenceError("writer lease operation/role 无效")
    if _release(record["release"]) != expected["release"]:
        raise WindowsWriterLeaseEvidenceError(
            "writer lease release 未绑定 SCM observation"
        )
    lease_nonce = record["lease_nonce"]
    if type(lease_nonce) is not str or _NONCE_192_RE.fullmatch(lease_nonce) is None:
        raise WindowsWriterLeaseEvidenceError("lease_nonce 必须是 192-bit lowercase hex")
    _positive_integer(
        record["lease_epoch"], label="lease_epoch", maximum=(1 << 63) - 1
    )
    _identifier(record["lease_id"], label="lease_id")
    if record["lease_id"] != _expected_lease_id(record):
        raise WindowsWriterLeaseEvidenceError("lease_id 不是 closed identity derivation")
    _holder(record["holder"], expected=expected)
    _lock_claim(record["lock"])
    record_hash = _self_hash(
        record, "lease_record_sha256", label="writer lease record"
    )
    for field in ("lease_id", "lease_nonce", "lease_epoch"):
        if claim[field] != record[field]:
            raise WindowsWriterLeaseEvidenceError(
                f"endpoint writer lease claim.{field} 与记录不一致"
            )
    if (
        claim["lease_record_sha256"] != record_hash
        or claim["authority"] != "claim_not_independently_observed"
    ):
        raise WindowsWriterLeaseEvidenceError(
            "endpoint writer lease claim 未绑定记录或越权"
        )
    return _clone(record, label="writer lease record")


def _kernel_observation(
    value: object,
    *,
    expected: Mapping[str, object],
    lock: Mapping[str, object],
) -> dict[str, object]:
    observation = _closed(
        value,
        {
            "source_process_pid",
            "source_process_creation_time_100ns",
            "source_handle_value",
            "duplicate_final_path",
            "duplicate_volume_serial_number",
            "duplicate_file_id",
            "duplicate_close_result",
            "conflict_open_result",
            "conflict_open_error_code",
            "kernel_observation_sha256",
        },
        label="writer kernel lock observation",
    )
    for field in (
        "source_process_pid",
        "source_process_creation_time_100ns",
        "source_handle_value",
        "duplicate_volume_serial_number",
        "conflict_open_error_code",
    ):
        maximum = _MAX_PERSISTED_HANDLE if field == "source_handle_value" else None
        _positive_integer(
            observation[field], label=f"writer kernel observation.{field}", maximum=maximum
        )
    if (
        observation["source_process_pid"] != expected["child_pid"]
        or observation["source_process_creation_time_100ns"]
        != expected["child_creation_time_100ns"]
        or observation["source_handle_value"] != lock["handle_value"]
        or observation["duplicate_final_path"] != WRITER_LOCK_FINAL_PATH
        or observation["duplicate_volume_serial_number"]
        != lock["volume_serial_number"]
        or observation["duplicate_file_id"] != lock["file_id"]
        or observation["duplicate_close_result"] != "closed_before_conflict_probe"
        or observation["conflict_open_result"] != "sharing_violation"
        or observation["conflict_open_error_code"] != _ERROR_SHARING_VIOLATION
    ):
        raise WindowsWriterLeaseEvidenceError(
            "kernel lock observation 未闭合 child handle／固定 D 文件／冲突 fence"
        )
    if (
        type(observation["duplicate_file_id"]) is not str
        or _HEX_128_RE.fullmatch(observation["duplicate_file_id"]) is None
    ):
        raise WindowsWriterLeaseEvidenceError("duplicate file_id 无效")
    _self_hash(
        observation,
        "kernel_observation_sha256",
        label="writer kernel lock observation",
    )
    return observation


def validate_windows_writer_lease_observation(
    value: object,
    scm_evidence: WindowsScmProcessObservationEvidence,
    endpoint_evidence: WindowsEndpointObservationEvidence,
) -> dict[str, object]:
    """验证可持久化 writer lease 观察；仍不形成 live 或 formal 资格。"""

    scm = _scm_document(scm_evidence)
    endpoint = _endpoint_document(endpoint_evidence, scm_evidence)
    expected = _identity_from_scm(scm)
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_scope",
            "scm_process_evidence_sha256",
            "endpoint_evidence_sha256",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "start_nonce",
            "state_identity_sha256",
            "release",
            "lease_record",
            "kernel_lock_observation",
            "observation_aggregate_sha256",
            "result",
            "evidence_sha256",
        },
        label="Windows writer lease observation",
    )
    if (
        evidence["schema_version"] != WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA
        or evidence["evidence_scope"] != WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE
        or evidence["result"] != "writer_lease_observed_not_canary_qualified"
        or evidence["scm_process_evidence_sha256"] != scm["evidence_sha256"]
        or evidence["endpoint_evidence_sha256"] != endpoint["evidence_sha256"]
    ):
        raise WindowsWriterLeaseEvidenceError(
            "writer lease schema/scope/result/upstream 不匹配"
        )
    for field in (
        "attempt_id",
        "nonce",
        "operation",
        "role",
        "start_nonce",
        "state_identity_sha256",
    ):
        if evidence[field] != expected[field]:
            raise WindowsWriterLeaseEvidenceError(
                f"writer lease observation.{field} 未绑定 SCM observation"
            )
    if _release(evidence["release"]) != expected["release"]:
        raise WindowsWriterLeaseEvidenceError(
            "writer lease observation release 未绑定 SCM observation"
        )
    record = validate_writer_lease_record(
        evidence["lease_record"], scm_evidence, endpoint_evidence
    )
    lock = record["lock"]
    if type(lock) is not dict:
        raise WindowsWriterLeaseEvidenceError("writer lock record 结构漂移")
    kernel = _kernel_observation(
        evidence["kernel_lock_observation"], expected=expected, lock=lock
    )
    aggregate = identity_sha256(
        [
            {"name": "scm_process", "sha256": scm["evidence_sha256"]},
            {"name": "endpoint", "sha256": endpoint["evidence_sha256"]},
            {"name": "lease_record", "sha256": record["lease_record_sha256"]},
            {
                "name": "kernel_lock",
                "sha256": kernel["kernel_observation_sha256"],
            },
        ]
    )
    if evidence["observation_aggregate_sha256"] != aggregate:
        raise WindowsWriterLeaseEvidenceError(
            "writer lease observation aggregate hash 不匹配"
        )
    _self_hash(
        evidence, "evidence_sha256", label="Windows writer lease observation"
    )
    return _clone(evidence, label="Windows writer lease observation")


@dataclass(frozen=True, slots=True)
class WindowsWriterLeaseObservationEvidence:
    """可持久化 writer lease observation；不是 process-local authority。"""

    _raw: bytes

    @classmethod
    def from_document(
        cls,
        value: object,
        scm_evidence: WindowsScmProcessObservationEvidence,
        endpoint_evidence: WindowsEndpointObservationEvidence,
    ) -> "WindowsWriterLeaseObservationEvidence":
        validated = validate_windows_writer_lease_observation(
            value, scm_evidence, endpoint_evidence
        )
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsWriterLeaseEvidenceError(
                "已验证 writer lease observation 类型漂移"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA",
    "WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE",
    "WRITER_LEASE_RECORD_FINAL_PATH",
    "WRITER_LEASE_RECORD_RELATIVE_PATH",
    "WRITER_LEASE_RECORD_SCHEMA",
    "WRITER_LOCK_FINAL_PATH",
    "WRITER_LOCK_RELATIVE_PATH",
    "WindowsWriterLeaseEvidenceError",
    "WindowsWriterLeaseObservationEvidence",
    "validate_windows_writer_lease_observation",
    "validate_writer_lease_record",
]
