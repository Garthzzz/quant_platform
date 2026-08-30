"""Steady writer lease 的 v2 closed observation-only evidence 合同。"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256
from .local_steady_windows_endpoint_evidence import (
    SteadyWindowsEndpointObservationEvidence,
    _expected as _steady_expected,
    _upstream as _steady_scm_upstream,
    validate_steady_windows_endpoint_observation,
)
from .local_steady_windows_scm_process_evidence import (
    SteadyWindowsScmProcessObservationEvidence,
)
from .local_windows_writer_lease_evidence import (
    WRITER_LEASE_RECORD_FINAL_PATH,
    WRITER_LEASE_RECORD_RELATIVE_PATH,
    WRITER_LOCK_FINAL_PATH,
    WRITER_LOCK_RELATIVE_PATH,
    WindowsWriterLeaseEvidenceError,
    _clone,
    _closed,
    _holder,
    _kernel_observation,
    _lock_claim,
    _positive_integer,
    _release,
    _self_hash,
    _sha256,
)


STEADY_WRITER_LEASE_RECORD_SCHEMA = "qrh-writer-lease-record/v2"
STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA = (
    "qrh-windows-writer-lease-observation/v2"
)
STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE = (
    "steady_writer_lease_observation_only"
)
_NONCE_192_RE = re.compile(r"^[0-9a-f]{48}$")


def _scm_document(
    evidence: SteadyWindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    try:
        return _steady_scm_upstream(evidence)
    except Exception as error:
        raise WindowsWriterLeaseEvidenceError(
            "steady writer 必须绑定 typed steady SCM evidence"
        ) from error


def _endpoint_document(
    evidence: SteadyWindowsEndpointObservationEvidence,
    scm_evidence: SteadyWindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not SteadyWindowsEndpointObservationEvidence:
        raise WindowsWriterLeaseEvidenceError(
            "steady writer 必须绑定 typed steady endpoint evidence"
        )
    try:
        return validate_steady_windows_endpoint_observation(
            evidence.as_dict(), scm_evidence
        )
    except Exception as error:
        raise WindowsWriterLeaseEvidenceError(
            "steady endpoint evidence 未绑定同一 SCM evidence"
        ) from error


def _endpoint_claim(
    endpoint: Mapping[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    probe = endpoint.get("probe")
    if type(probe) is not dict:
        raise WindowsWriterLeaseEvidenceError("steady endpoint probe 结构无效")
    response = probe.get("response")
    if type(response) is not dict:
        raise WindowsWriterLeaseEvidenceError("steady endpoint response 结构无效")
    lease = _closed(
        response.get("writer_lease"),
        {
            "lease_id",
            "lease_nonce",
            "lease_epoch",
            "lease_record_sha256",
            "authority",
        },
        label="steady endpoint writer lease claim",
    )
    return response, lease


def _expected_lease_id(record: Mapping[str, object]) -> str:
    return "steady-lease-" + identity_sha256(
        {
            "boot_nonce": record["boot_nonce"],
            "active_release_sha256": record["active_release_sha256"],
            "binding_sha256": record["binding_sha256"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
            "job_identity_sha256": record["job_identity_sha256"],
        }
    )[:32]


def validate_steady_writer_lease_record(
    value: object,
    scm_evidence: SteadyWindowsScmProcessObservationEvidence,
    endpoint_evidence: SteadyWindowsEndpointObservationEvidence,
) -> dict[str, object]:
    scm = _scm_document(scm_evidence)
    endpoint = _endpoint_document(endpoint_evidence, scm_evidence)
    expected = _steady_expected(scm)
    response, claim = _endpoint_claim(endpoint)
    record = _closed(
        value,
        {
            "schema_version",
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
            "lease_id",
            "lease_nonce",
            "lease_epoch",
            "holder",
            "lock",
            "job_identity_sha256",
            "admission_binding_sha256",
            "lease_record_sha256",
        },
        label="steady writer lease record",
    )
    if record["schema_version"] != STEADY_WRITER_LEASE_RECORD_SCHEMA:
        raise WindowsWriterLeaseEvidenceError("steady writer record schema 不匹配")
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
        if record[field] != expected[field]:
            raise WindowsWriterLeaseEvidenceError(
                f"steady writer record.{field} 未绑定 SCM observation"
            )
    if _release(record["release"]) != expected["release"]:
        raise WindowsWriterLeaseEvidenceError(
            "steady writer record release 未绑定 SCM observation"
        )
    if (
        type(record["lease_nonce"]) is not str
        or _NONCE_192_RE.fullmatch(record["lease_nonce"]) is None
    ):
        raise WindowsWriterLeaseEvidenceError(
            "steady lease_nonce 必须是 192-bit lowercase hex"
        )
    _positive_integer(record["lease_epoch"], label="steady lease_epoch")
    if record["lease_id"] != _expected_lease_id(record):
        raise WindowsWriterLeaseEvidenceError(
            "steady lease_id 不是 closed identity derivation"
        )
    _holder(record["holder"], expected=expected)
    _lock_claim(record["lock"])
    _sha256(record["job_identity_sha256"], label="job_identity_sha256")
    _sha256(
        record["admission_binding_sha256"],
        label="admission_binding_sha256",
    )
    if (
        record["job_identity_sha256"]
        != response.get("job_identity_sha256")
        or record["admission_binding_sha256"]
        != response.get("admission_binding_sha256")
    ):
        raise WindowsWriterLeaseEvidenceError(
            "steady writer job/admission claim 未绑定 endpoint"
        )
    record_hash = _self_hash(
        record, "lease_record_sha256", label="steady writer lease record"
    )
    for field in ("lease_id", "lease_nonce", "lease_epoch"):
        if claim[field] != record[field]:
            raise WindowsWriterLeaseEvidenceError(
                f"steady endpoint writer claim.{field} 与记录不一致"
            )
    if (
        claim["lease_record_sha256"] != record_hash
        or claim["authority"] != "claim_not_independently_observed"
    ):
        raise WindowsWriterLeaseEvidenceError(
            "steady endpoint writer claim 未绑定记录或越权"
        )
    return _clone(record, label="steady writer lease record")


def validate_steady_windows_writer_lease_observation(
    value: object,
    scm_evidence: SteadyWindowsScmProcessObservationEvidence,
    endpoint_evidence: SteadyWindowsEndpointObservationEvidence,
) -> dict[str, object]:
    scm = _scm_document(scm_evidence)
    endpoint = _endpoint_document(endpoint_evidence, scm_evidence)
    expected = _steady_expected(scm)
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_scope",
            "scm_process_evidence_sha256",
            "endpoint_evidence_sha256",
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
            "lease_record",
            "kernel_lock_observation",
            "observation_aggregate_sha256",
            "result",
            "evidence_sha256",
        },
        label="steady Windows writer lease observation",
    )
    if (
        evidence["schema_version"]
        != STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA
        or evidence["evidence_scope"]
        != STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE
        or evidence["scm_process_evidence_sha256"] != scm["evidence_sha256"]
        or evidence["endpoint_evidence_sha256"]
        != endpoint["evidence_sha256"]
        or evidence["result"]
        != "steady_writer_lease_observed_not_admission_qualified"
    ):
        raise WindowsWriterLeaseEvidenceError(
            "steady writer schema/scope/upstream/result 不匹配"
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
            raise WindowsWriterLeaseEvidenceError(
                f"steady writer observation.{field} 未绑定 SCM observation"
            )
    if _release(evidence["release"]) != expected["release"]:
        raise WindowsWriterLeaseEvidenceError("steady writer release 漂移")
    record = validate_steady_writer_lease_record(
        evidence["lease_record"], scm_evidence, endpoint_evidence
    )
    lock = record.get("lock")
    if type(lock) is not dict:
        raise WindowsWriterLeaseEvidenceError("steady writer lock 结构漂移")
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
        raise WindowsWriterLeaseEvidenceError("steady writer aggregate 不匹配")
    _self_hash(
        evidence,
        "evidence_sha256",
        label="steady Windows writer lease observation",
    )
    return _clone(evidence, label="steady Windows writer lease observation")


@dataclass(frozen=True, slots=True)
class SteadyWindowsWriterLeaseObservationEvidence:
    _raw: bytes

    @classmethod
    def from_document(
        cls,
        value: object,
        scm_evidence: SteadyWindowsScmProcessObservationEvidence,
        endpoint_evidence: SteadyWindowsEndpointObservationEvidence,
    ) -> "SteadyWindowsWriterLeaseObservationEvidence":
        validated = validate_steady_windows_writer_lease_observation(
            value, scm_evidence, endpoint_evidence
        )
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsWriterLeaseEvidenceError(
                "已验证 steady writer observation 类型漂移"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA",
    "STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE",
    "STEADY_WRITER_LEASE_RECORD_SCHEMA",
    "SteadyWindowsWriterLeaseObservationEvidence",
    "validate_steady_windows_writer_lease_observation",
    "validate_steady_writer_lease_record",
]
