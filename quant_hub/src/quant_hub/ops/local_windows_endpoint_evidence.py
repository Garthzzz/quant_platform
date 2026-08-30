"""Windows 生产端点身份观察的纯 closed-schema 合同。

本模块不访问网络、不查询 TCP table，也不形成 writer lease 或部署资格。文档只记录
一个由 live SCM/process 观察夹住的端点事实；即使全部哈希正确，仍必须由后续
writer-lease/fence 聚合器消费不可反序列化的现场能力后才可能形成资格。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256
from .local_windows_scm_process_evidence import (
    WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    WindowsScmProcessObservationEvidence,
)


WINDOWS_ENDPOINT_OBSERVATION_SCHEMA = "qrh-windows-endpoint-observation/v1"
WINDOWS_ENDPOINT_OBSERVATION_SCOPE = "endpoint_identity_observation_only"
EXACT_RUNTIME_ENDPOINT_SCHEMA = "qrh-exact-runtime-endpoint/v1"

_OPERATIONS = {"activation", "rollback", "bootstrap_first_pair"}
_ROLES = {"prior", "candidate", "baseline"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{48}$")
_RELEASE_PREFIX = "D:\\quant\\quant_platform\\releases\\"
_MAX_ENDPOINT_BODY_BYTES = 64 * 1024


class WindowsEndpointEvidenceError(RuntimeError):
    """端点观察文档不是 closed、canonical 或未绑定上游观察。"""


def _clone(value: object, *, label: str) -> dict[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except Exception as error:
        raise WindowsEndpointEvidenceError(f"{label} 不是 canonical JSON") from error
    if type(cloned) is not dict:
        raise WindowsEndpointEvidenceError(f"{label} 必须是 JSON object")
    return cloned


def _closed(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise WindowsEndpointEvidenceError(f"{label} schema 不闭合")
    return value


def _identifier(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _IDENTIFIER_RE.fullmatch(value) is None
        or value.endswith((".", " "))
    ):
        raise WindowsEndpointEvidenceError(f"{label} identifier 无效")
    return value


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise WindowsEndpointEvidenceError(f"{label} SHA-256 无效")
    return value


def _positive_integer(value: object, *, label: str) -> int:
    if type(value) is not int or value < 1:
        raise WindowsEndpointEvidenceError(f"{label} 必须是正整数")
    return value


def _self_hash(document: Mapping[str, object], field: str, *, label: str) -> str:
    claimed = _sha256(document[field], label=f"{label}.{field}")
    material = dict(document)
    material.pop(field)
    if identity_sha256(material) != claimed:
        raise WindowsEndpointEvidenceError(f"{label} self hash 不匹配")
    return claimed


def _release(value: object) -> dict[str, object]:
    release = _closed(
        value,
        {"release_id", "release_path", "manifest_sha256"},
        label="release",
    )
    release_id = _identifier(release["release_id"], label="release_id")
    if release["release_path"] != _RELEASE_PREFIX + release_id:
        raise WindowsEndpointEvidenceError("release_path 不是 exact D release path")
    _sha256(release["manifest_sha256"], label="release.manifest_sha256")
    return release


def _upstream_document(
    evidence: WindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not WindowsScmProcessObservationEvidence:
        raise WindowsEndpointEvidenceError(
            "endpoint evidence 必须绑定 typed SCM/process observation evidence"
        )
    try:
        upstream = evidence.as_dict()
    except Exception as error:
        raise WindowsEndpointEvidenceError("SCM/process observation 不可读取") from error
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
    _closed(upstream, required, label="SCM/process observation")
    if (
        upstream["schema_version"] != WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA
        or upstream["evidence_scope"] != WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE
        or upstream["result"] != "identity_observed_not_writer_qualified"
    ):
        raise WindowsEndpointEvidenceError("上游 SCM/process observation 权限边界不同")
    _self_hash(upstream, "evidence_sha256", label="SCM/process observation")
    return upstream


def _upstream_identity(upstream: Mapping[str, object]) -> dict[str, object]:
    service = upstream.get("service")
    host = upstream.get("host")
    child = upstream.get("child")
    if not all(type(value) is dict for value in (service, host, child)):
        raise WindowsEndpointEvidenceError("SCM/process identity 结构无效")
    status = service.get("status")  # type: ignore[union-attr]
    if type(status) is not dict:
        raise WindowsEndpointEvidenceError("SCM service status 结构无效")
    identity = {
        "attempt_id": upstream["attempt_id"],
        "nonce": upstream["nonce"],
        "operation": upstream["operation"],
        "role": upstream["role"],
        "start_nonce": upstream["start_nonce"],
        "authorization_sha256": upstream["authorization_sha256"],
        "scm_identity_sha256": upstream["scm_identity_sha256"],
        "state_identity_sha256": upstream["state_identity_sha256"],
        "release": upstream["release"],
        "service_name": service.get("service_name"),  # type: ignore[union-attr]
        "host_pid": host.get("pid"),  # type: ignore[union-attr]
        "host_creation_time_100ns": host.get("creation_time_100ns"),  # type: ignore[union-attr]
        "child_pid": child.get("pid"),  # type: ignore[union-attr]
        "child_creation_time_100ns": child.get("creation_time_100ns"),  # type: ignore[union-attr]
    }
    if status.get("process_id") != identity["host_pid"]:
        raise WindowsEndpointEvidenceError("SCM status 与 host PID 不一致")
    for field in ("host_pid", "host_creation_time_100ns", "child_pid", "child_creation_time_100ns"):
        _positive_integer(identity[field], label=field)
    return identity


def _listener(value: object, *, child_pid: int, label: str) -> dict[str, object]:
    listener = _closed(
        value,
        {
            "address_family",
            "local_address",
            "local_port",
            "state",
            "owning_pid",
            "listener_identity_sha256",
        },
        label=label,
    )
    _positive_integer(listener["local_port"], label=f"{label}.local_port")
    _positive_integer(listener["owning_pid"], label=f"{label}.owning_pid")
    if (
        listener["address_family"] != "AF_INET"
        or listener["local_address"] != "0.0.0.0"
        or listener["local_port"] != 8765
        or listener["state"] != "LISTEN"
        or listener["owning_pid"] != child_pid
    ):
        raise WindowsEndpointEvidenceError(
            f"{label} 不是 child 独占的固定 IPv4 production listener"
        )
    _self_hash(listener, "listener_identity_sha256", label=label)
    return listener


def _lease_claim(value: object) -> dict[str, object]:
    lease = _closed(
        value,
        {
            "lease_id",
            "lease_nonce",
            "lease_epoch",
            "lease_record_sha256",
            "authority",
        },
        label="writer lease claim",
    )
    _identifier(lease["lease_id"], label="lease_id")
    _identifier(lease["lease_nonce"], label="lease_nonce")
    _positive_integer(lease["lease_epoch"], label="lease_epoch")
    _sha256(lease["lease_record_sha256"], label="lease_record_sha256")
    if lease["authority"] != "claim_not_independently_observed":
        raise WindowsEndpointEvidenceError("endpoint 不得自授 writer lease authority")
    return lease


def _endpoint_claim(
    value: object,
    *,
    challenge: str,
    expected: Mapping[str, object],
) -> dict[str, object]:
    claim = _closed(
        value,
        {
            "schema_version",
            "status",
            "probe_challenge",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "start_nonce",
            "authorization_sha256",
            "scm_identity_sha256",
            "state_identity_sha256",
            "release",
            "service",
            "child",
            "listener",
            "writer_lease",
            "endpoint_claim_sha256",
        },
        label="endpoint response",
    )
    if (
        claim["schema_version"] != EXACT_RUNTIME_ENDPOINT_SCHEMA
        or claim["status"] != "identity_claim_only"
        or claim["probe_challenge"] != challenge
    ):
        raise WindowsEndpointEvidenceError("endpoint response schema/status/challenge 不匹配")
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
        if claim[field] != expected[field]:
            raise WindowsEndpointEvidenceError(f"endpoint response.{field} 未绑定 SCM observation")
    if _release(claim["release"]) != expected["release"]:
        raise WindowsEndpointEvidenceError("endpoint response release 未绑定 SCM observation")
    service = _closed(
        claim["service"],
        {"service_name", "host_pid", "host_creation_time_100ns"},
        label="endpoint service identity",
    )
    child = _closed(
        claim["child"],
        {"child_pid", "child_creation_time_100ns"},
        label="endpoint child identity",
    )
    listener = _closed(
        claim["listener"],
        {"local_address", "local_port"},
        label="endpoint listener claim",
    )
    for field in ("host_pid", "host_creation_time_100ns"):
        _positive_integer(service[field], label=f"endpoint service identity.{field}")
    for field in ("child_pid", "child_creation_time_100ns"):
        _positive_integer(child[field], label=f"endpoint child identity.{field}")
    _positive_integer(
        listener["local_port"], label="endpoint listener claim.local_port"
    )
    if (
        service != {
            "service_name": expected["service_name"],
            "host_pid": expected["host_pid"],
            "host_creation_time_100ns": expected["host_creation_time_100ns"],
        }
        or child != {
            "child_pid": expected["child_pid"],
            "child_creation_time_100ns": expected["child_creation_time_100ns"],
        }
        or listener != {"local_address": "0.0.0.0", "local_port": 8765}
    ):
        raise WindowsEndpointEvidenceError("endpoint process/listener identity 未绑定 SCM observation")
    _lease_claim(claim["writer_lease"])
    _self_hash(claim, "endpoint_claim_sha256", label="endpoint response")
    return claim


def _probe(
    value: object,
    *,
    expected: Mapping[str, object],
) -> dict[str, object]:
    probe = _closed(
        value,
        {
            "scheme",
            "host",
            "port",
            "path",
            "method",
            "challenge",
            "status_code",
            "content_type",
            "content_length",
            "body_sha256",
            "response",
            "probe_identity_sha256",
        },
        label="endpoint probe",
    )
    challenge = probe["challenge"]
    if type(challenge) is not str or _CHALLENGE_RE.fullmatch(challenge) is None:
        raise WindowsEndpointEvidenceError("endpoint challenge 必须是 192-bit lowercase hex")
    _positive_integer(probe["port"], label="endpoint probe.port")
    _positive_integer(probe["status_code"], label="endpoint probe.status_code")
    if (
        probe["scheme"] != "http"
        or probe["host"] != "127.0.0.1"
        or probe["port"] != 8765
        or probe["path"] != "/deploymentz"
        or probe["method"] != "GET"
        or probe["status_code"] != 200
        or probe["content_type"] != "application/json"
    ):
        raise WindowsEndpointEvidenceError("endpoint probe 不是固定 loopback HTTP contract")
    content_length = _positive_integer(probe["content_length"], label="content_length")
    if content_length > _MAX_ENDPOINT_BODY_BYTES:
        raise WindowsEndpointEvidenceError("endpoint content_length 超过固定上限")
    response = _endpoint_claim(probe["response"], challenge=challenge, expected=expected)
    body = canonical_bytes(response)
    if probe["content_length"] != len(body):
        raise WindowsEndpointEvidenceError("endpoint content_length 与 canonical body 不一致")
    if probe["body_sha256"] != identity_sha256(response):
        raise WindowsEndpointEvidenceError("endpoint body SHA-256 不匹配")
    _self_hash(probe, "probe_identity_sha256", label="endpoint probe")
    return probe


def validate_windows_endpoint_observation(
    value: object,
    scm_evidence: WindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    """验证持久端点观察；返回值仍不是现场能力或 writer 资格。"""

    upstream = _upstream_document(scm_evidence)
    expected = _upstream_identity(upstream)
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_scope",
            "scm_process_evidence_sha256",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "start_nonce",
            "state_identity_sha256",
            "release",
            "listener_before",
            "probe",
            "listener_after",
            "observation_aggregate_sha256",
            "result",
            "evidence_sha256",
        },
        label="Windows endpoint observation",
    )
    if (
        evidence["schema_version"] != WINDOWS_ENDPOINT_OBSERVATION_SCHEMA
        or evidence["evidence_scope"] != WINDOWS_ENDPOINT_OBSERVATION_SCOPE
        or evidence["result"] != "endpoint_observed_not_writer_qualified"
        or evidence["scm_process_evidence_sha256"] != upstream["evidence_sha256"]
    ):
        raise WindowsEndpointEvidenceError("endpoint observation schema/scope/upstream 不匹配")
    for field in ("attempt_id", "nonce", "operation", "role", "start_nonce", "state_identity_sha256"):
        if evidence[field] != expected[field]:
            raise WindowsEndpointEvidenceError(f"endpoint observation.{field} 未绑定 SCM observation")
    if evidence["operation"] not in _OPERATIONS or evidence["role"] not in _ROLES:
        raise WindowsEndpointEvidenceError("endpoint operation/role 不属于 exact state machine")
    if _release(evidence["release"]) != expected["release"]:
        raise WindowsEndpointEvidenceError("endpoint observation release 未绑定 SCM observation")
    child_pid = int(expected["child_pid"])
    before = _listener(evidence["listener_before"], child_pid=child_pid, label="listener_before")
    probe = _probe(evidence["probe"], expected=expected)
    after = _listener(evidence["listener_after"], child_pid=child_pid, label="listener_after")
    if before != after:
        raise WindowsEndpointEvidenceError("HTTP probe 前后 listener identity 漂移")
    aggregate = identity_sha256(
        [
            {"name": "scm_process", "sha256": upstream["evidence_sha256"]},
            {"name": "listener_before", "sha256": before["listener_identity_sha256"]},
            {"name": "probe", "sha256": probe["probe_identity_sha256"]},
            {"name": "listener_after", "sha256": after["listener_identity_sha256"]},
        ]
    )
    if evidence["observation_aggregate_sha256"] != aggregate:
        raise WindowsEndpointEvidenceError("endpoint observation aggregate hash 不匹配")
    _self_hash(evidence, "evidence_sha256", label="Windows endpoint observation")
    return _clone(evidence, label="Windows endpoint observation")


@dataclass(frozen=True, slots=True)
class WindowsEndpointObservationEvidence:
    """可持久化 endpoint observation；不是 process-local authority。"""

    _raw: bytes

    @classmethod
    def from_document(
        cls,
        value: object,
        scm_evidence: WindowsScmProcessObservationEvidence,
    ) -> "WindowsEndpointObservationEvidence":
        validated = validate_windows_endpoint_observation(value, scm_evidence)
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsEndpointEvidenceError("已验证 endpoint observation 类型漂移")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "EXACT_RUNTIME_ENDPOINT_SCHEMA",
    "WINDOWS_ENDPOINT_OBSERVATION_SCHEMA",
    "WINDOWS_ENDPOINT_OBSERVATION_SCOPE",
    "WindowsEndpointEvidenceError",
    "WindowsEndpointObservationEvidence",
    "validate_windows_endpoint_observation",
]
