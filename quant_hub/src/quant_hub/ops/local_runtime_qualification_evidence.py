"""Closed persistent aggregate for e.4.3 transient runtime observations.

The document records only canonical hashes.  It is replayable audit evidence,
never a live deployment capability and never a source from which qualification
can be reconstructed.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256


LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA = (
    "qrh-local-runtime-qualification-evidence/v1"
)
LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE = (
    "observation_evidence_only_not_authority"
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATIONS = {"activation", "rollback", "bootstrap_first_pair"}
_ROLES = {"prior", "candidate", "baseline"}
_FIELDS = {
    "schema_version",
    "scope",
    "attempt_id",
    "nonce",
    "operation",
    "role",
    "start_nonce",
    "state_identity_sha256",
    "authorization_sha256",
    "release_compatibility_sha256",
    "release_closure_sha256",
    "production_state_before_order_sha256",
    "production_state_after_order_sha256",
    "scm_before_after_sha256",
    "endpoint_before_after_sha256",
    "writer_before_after_sha256",
    "canary_request_sha256",
    "canary_result_sha256",
    "canary_database_order_sha256",
    "runtime_tooling_manifest_sha256",
    "controller_tooling_observation_sha256",
    "aggregate_sha256",
}
_HASH_FIELDS = _FIELDS - {
    "schema_version",
    "scope",
    "attempt_id",
    "nonce",
    "operation",
    "role",
    "start_nonce",
    "aggregate_sha256",
}


class LocalRuntimeQualificationEvidenceError(ValueError):
    """The persistent observation aggregate violates its closed schema."""


def _closed(value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification evidence 必须是 object"
        )
    if set(value) != _FIELDS:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification evidence schema 不闭合"
        )
    return value


def _identifier(value: object, *, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise LocalRuntimeQualificationEvidenceError(f"{label} 无效")
    return value


def _sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise LocalRuntimeQualificationEvidenceError(f"{label} SHA-256 无效")
    return value


def validate_local_runtime_qualification_evidence(
    value: object,
) -> Mapping[str, object]:
    document = _closed(value)
    if (
        document["schema_version"]
        != LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA
        or document["scope"] != LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE
    ):
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification evidence schema/scope 漂移"
        )
    _identifier(document["attempt_id"], label="attempt_id")
    _identifier(document["nonce"], label="nonce")
    _identifier(document["start_nonce"], label="start_nonce")
    if type(document["operation"]) is not str or document["operation"] not in _OPERATIONS:
        raise LocalRuntimeQualificationEvidenceError("operation 不属于固定枚举")
    if type(document["role"]) is not str or document["role"] not in _ROLES:
        raise LocalRuntimeQualificationEvidenceError("role 不属于固定枚举")
    if document["operation"] == "bootstrap_first_pair":
        if document["role"] != "baseline":
            raise LocalRuntimeQualificationEvidenceError(
                "bootstrap formal aggregate 只允许 baseline"
            )
    elif document["role"] == "baseline":
        raise LocalRuntimeQualificationEvidenceError(
            "ordinary formal aggregate 不允许 baseline"
        )
    for field in _HASH_FIELDS:
        _sha256(document[field], label=field)
    aggregate = _sha256(document["aggregate_sha256"], label="aggregate_sha256")
    expected = identity_sha256(
        {key: item for key, item in document.items() if key != "aggregate_sha256"}
    )
    if aggregate != expected:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification aggregate self hash 不匹配"
        )
    return document


def build_local_runtime_qualification_evidence(
    payload: Mapping[str, object],
) -> Mapping[str, object]:
    if type(payload) is not dict or "aggregate_sha256" in payload:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification payload 必须是无 self hash 的 exact object"
        )
    document = dict(payload)
    document["aggregate_sha256"] = identity_sha256(document)
    return validate_local_runtime_qualification_evidence(document)


def _strict_json(raw: bytes) -> object:
    if type(raw) is not bytes or not raw:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification evidence bytes 无效"
        )

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise LocalRuntimeQualificationEvidenceError(
                    "runtime qualification evidence JSON 存在重复 key"
                )
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                LocalRuntimeQualificationEvidenceError(
                    f"runtime qualification evidence 非法常量: {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification evidence 不是 strict UTF-8 JSON"
        ) from error


def parse_local_runtime_qualification_evidence_bytes(
    raw: bytes,
) -> "LocalRuntimeQualificationAggregateEvidence":
    value = _strict_json(raw)
    evidence = LocalRuntimeQualificationAggregateEvidence.from_document(value)
    if evidence.canonical_bytes() != raw:
        raise LocalRuntimeQualificationEvidenceError(
            "runtime qualification evidence bytes 非 canonical"
        )
    return evidence


@dataclass(frozen=True, slots=True)
class LocalRuntimeQualificationAggregateEvidence:
    """Typed persistent evidence; deliberately exposes no qualify/consume API."""

    _raw: bytes

    @classmethod
    def from_document(
        cls, value: object
    ) -> "LocalRuntimeQualificationAggregateEvidence":
        document = validate_local_runtime_qualification_evidence(value)
        return cls(canonical_bytes(document))

    def as_dict(self) -> dict[str, object]:
        value = _strict_json(self._raw)
        if type(value) is not dict:
            raise LocalRuntimeQualificationEvidenceError(
                "runtime qualification evidence 内部 bytes 损坏"
            )
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def aggregate_sha256(self) -> str:
        return str(self.as_dict()["aggregate_sha256"])


__all__ = [
    "LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA",
    "LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE",
    "LocalRuntimeQualificationAggregateEvidence",
    "LocalRuntimeQualificationEvidenceError",
    "build_local_runtime_qualification_evidence",
    "parse_local_runtime_qualification_evidence_bytes",
    "validate_local_runtime_qualification_evidence",
]
