"""Steady endpoint 的 v2 closed observation-only evidence 合同。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256
from .local_steady_windows_scm_process_evidence import (
    STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    SteadyWindowsScmProcessObservationEvidence,
)
from .local_windows_endpoint_evidence import (
    WindowsEndpointEvidenceError,
    _clone,
    _closed,
    _lease_claim,
    _listener,
    _positive_integer,
    _release,
    _self_hash,
    _sha256,
)


STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCHEMA = (
    "qrh-windows-endpoint-observation/v2"
)
STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE = (
    "steady_endpoint_identity_observation_only"
)
STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA = "qrh-exact-runtime-endpoint/v2"
_CHALLENGE_LENGTH = 48
_MAX_ENDPOINT_BODY_BYTES = 64 * 1024
_ADMISSION_STATES = {"closed_pending_promotion", "ack_pending", "admitted"}


def _upstream(
    evidence: SteadyWindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not SteadyWindowsScmProcessObservationEvidence:
        raise WindowsEndpointEvidenceError(
            "steady endpoint 必须绑定 typed steady SCM evidence"
        )
    upstream = evidence.as_dict()
    _closed(
        upstream,
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
        label="steady SCM/process observation",
    )
    if (
        upstream["schema_version"]
        != STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA
        or upstream["evidence_scope"]
        != STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE
        or upstream["authority_kind"] != "steady_active"
        or upstream["runtime_state_kind"] != "steady_current"
        or upstream["result"]
        != "steady_identity_observed_not_writer_qualified"
    ):
        raise WindowsEndpointEvidenceError(
            "上游 steady SCM/process 权限边界不同"
        )
    _self_hash(upstream, "evidence_sha256", label="steady SCM observation")
    return upstream


def _expected(upstream: Mapping[str, object]) -> dict[str, object]:
    service = upstream.get("service")
    host = upstream.get("host")
    child = upstream.get("child")
    if not all(type(value) is dict for value in (service, host, child)):
        raise WindowsEndpointEvidenceError("steady SCM process identity 结构无效")
    status = service.get("status")  # type: ignore[union-attr]
    if type(status) is not dict:
        raise WindowsEndpointEvidenceError("steady SCM service status 结构无效")
    expected = {
        field: upstream[field]
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
            "release",
        )
    }
    expected.update(
        {
            "service_name": service.get("service_name"),  # type: ignore[union-attr]
            "host_pid": host.get("pid"),  # type: ignore[union-attr]
            "host_creation_time_100ns": host.get("creation_time_100ns"),  # type: ignore[union-attr]
            "child_pid": child.get("pid"),  # type: ignore[union-attr]
            "child_creation_time_100ns": child.get("creation_time_100ns"),  # type: ignore[union-attr]
        }
    )
    if status.get("process_id") != expected["host_pid"]:
        raise WindowsEndpointEvidenceError("steady SCM status/host PID 不一致")
    for field in (
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
    ):
        _positive_integer(expected[field], label=field)
    return expected


def _steady_claim(
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
            "child",
            "listener",
            "writer_lease",
            "job_identity_sha256",
            "admission_binding_sha256",
            "admission_state",
            "endpoint_claim_sha256",
        },
        label="steady endpoint response",
    )
    if (
        claim["schema_version"] != STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA
        or claim["status"] != "steady_identity_claim_only"
        or claim["probe_challenge"] != challenge
        or claim["authority_kind"] != "steady_active"
        or claim["runtime_state_kind"] != "steady_current"
    ):
        raise WindowsEndpointEvidenceError(
            "steady endpoint response schema/status/challenge 不匹配"
        )
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
        if claim[field] != expected[field]:
            raise WindowsEndpointEvidenceError(
                f"steady endpoint response.{field} 未绑定 SCM observation"
            )
    if _release(claim["release"]) != expected["release"]:
        raise WindowsEndpointEvidenceError(
            "steady endpoint release 未绑定 SCM observation"
        )
    service = _closed(
        claim["service"],
        {"service_name", "host_pid", "host_creation_time_100ns"},
        label="steady endpoint service",
    )
    child = _closed(
        claim["child"],
        {"child_pid", "child_creation_time_100ns"},
        label="steady endpoint child",
    )
    listener = _closed(
        claim["listener"],
        {"local_address", "local_port"},
        label="steady endpoint listener claim",
    )
    if (
        service
        != {
            "service_name": expected["service_name"],
            "host_pid": expected["host_pid"],
            "host_creation_time_100ns": expected[
                "host_creation_time_100ns"
            ],
        }
        or child
        != {
            "child_pid": expected["child_pid"],
            "child_creation_time_100ns": expected[
                "child_creation_time_100ns"
            ],
        }
        or listener != {"local_address": "0.0.0.0", "local_port": 8765}
    ):
        raise WindowsEndpointEvidenceError(
            "steady endpoint process/listener claim 未绑定 SCM observation"
        )
    _lease_claim(claim["writer_lease"])
    _sha256(claim["job_identity_sha256"], label="job_identity_sha256")
    _sha256(
        claim["admission_binding_sha256"],
        label="admission_binding_sha256",
    )
    if claim["admission_state"] not in _ADMISSION_STATES:
        raise WindowsEndpointEvidenceError("steady admission_state 不属于闭集")
    _self_hash(claim, "endpoint_claim_sha256", label="steady endpoint response")
    return claim


def _probe(
    value: object, *, expected: Mapping[str, object]
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
        label="steady endpoint probe",
    )
    challenge = probe["challenge"]
    if (
        type(challenge) is not str
        or len(challenge) != _CHALLENGE_LENGTH
        or any(character not in "0123456789abcdef" for character in challenge)
    ):
        raise WindowsEndpointEvidenceError("steady endpoint challenge 无效")
    if (
        probe["scheme"] != "http"
        or probe["host"] != "127.0.0.1"
        or probe["port"] != 8765
        or probe["path"] != "/deploymentz"
        or probe["method"] != "GET"
        or probe["status_code"] != 200
        or probe["content_type"] != "application/json"
    ):
        raise WindowsEndpointEvidenceError("steady endpoint probe 不是固定合同")
    content_length = _positive_integer(
        probe["content_length"], label="steady content_length"
    )
    if content_length > _MAX_ENDPOINT_BODY_BYTES:
        raise WindowsEndpointEvidenceError("steady endpoint body 超过固定上限")
    response = _steady_claim(
        probe["response"], challenge=challenge, expected=expected
    )
    body = canonical_bytes(response)
    if (
        content_length != len(body)
        or probe["body_sha256"] != hashlib.sha256(body).hexdigest()
    ):
        raise WindowsEndpointEvidenceError(
            "steady endpoint body length/hash 不匹配"
        )
    _self_hash(probe, "probe_identity_sha256", label="steady endpoint probe")
    return probe


def validate_steady_windows_endpoint_observation(
    value: object,
    scm_evidence: SteadyWindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    upstream = _upstream(scm_evidence)
    expected = _expected(upstream)
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_scope",
            "scm_process_evidence_sha256",
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
            "release",
            "listener_before",
            "probe",
            "listener_after",
            "observation_aggregate_sha256",
            "result",
            "evidence_sha256",
        },
        label="steady Windows endpoint observation",
    )
    if (
        evidence["schema_version"]
        != STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCHEMA
        or evidence["evidence_scope"]
        != STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE
        or evidence["scm_process_evidence_sha256"]
        != upstream["evidence_sha256"]
        or evidence["result"]
        != "steady_endpoint_observed_not_writer_qualified"
    ):
        raise WindowsEndpointEvidenceError(
            "steady endpoint schema/scope/upstream/result 不匹配"
        )
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
    ):
        if evidence[field] != expected[field]:
            raise WindowsEndpointEvidenceError(
                f"steady endpoint observation.{field} 未绑定 SCM observation"
            )
    if _release(evidence["release"]) != expected["release"]:
        raise WindowsEndpointEvidenceError("steady endpoint release 漂移")
    child_pid = int(expected["child_pid"])
    before = _listener(
        evidence["listener_before"],
        child_pid=child_pid,
        label="steady listener_before",
    )
    probe = _probe(evidence["probe"], expected=expected)
    after = _listener(
        evidence["listener_after"],
        child_pid=child_pid,
        label="steady listener_after",
    )
    if before != after:
        raise WindowsEndpointEvidenceError("steady endpoint listener 漂移")
    aggregate = identity_sha256(
        [
            {"name": "scm_process", "sha256": upstream["evidence_sha256"]},
            {
                "name": "listener_before",
                "sha256": before["listener_identity_sha256"],
            },
            {"name": "probe", "sha256": probe["probe_identity_sha256"]},
            {
                "name": "listener_after",
                "sha256": after["listener_identity_sha256"],
            },
        ]
    )
    if evidence["observation_aggregate_sha256"] != aggregate:
        raise WindowsEndpointEvidenceError("steady endpoint aggregate 不匹配")
    _self_hash(
        evidence,
        "evidence_sha256",
        label="steady Windows endpoint observation",
    )
    return _clone(evidence, label="steady Windows endpoint observation")


@dataclass(frozen=True, slots=True)
class SteadyWindowsEndpointObservationEvidence:
    _raw: bytes

    @classmethod
    def from_document(
        cls,
        value: object,
        scm_evidence: SteadyWindowsScmProcessObservationEvidence,
    ) -> "SteadyWindowsEndpointObservationEvidence":
        validated = validate_steady_windows_endpoint_observation(
            value, scm_evidence
        )
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsEndpointEvidenceError(
                "已验证 steady endpoint observation 类型漂移"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA",
    "STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCHEMA",
    "STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE",
    "SteadyWindowsEndpointObservationEvidence",
    "validate_steady_windows_endpoint_observation",
]
