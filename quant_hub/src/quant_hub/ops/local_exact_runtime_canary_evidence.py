"""Exact runtime SQLite canary 的纯持久 closed-schema 合同。

request 只描述 B2 attempt 隔离副本；result 只记录 child 自报的同租约执行结果。
两者均可复制和重放，绝不构成 live lease、canary capability 或 deployment
qualification。后续 controller 必须以不可序列化的 SCM/endpoint/writer observation
夹住真实执行并重新验证数据库。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping

from .local_release_identity import canonical_bytes, identity_sha256


EXACT_RUNTIME_CANARY_REQUEST_SCHEMA = "qrh-exact-runtime-canary-request/v1"
EXACT_RUNTIME_CANARY_REQUEST_SCOPE = "exact_runtime_canary_request_only"
EXACT_RUNTIME_CANARY_EVIDENCE_SCHEMA = "qrh-exact-runtime-canary-evidence/v1"
EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE = "exact_runtime_canary_evidence_only"
EXACT_RUNTIME_CANARY_RESULT = (
    "exact_runtime_canary_observed_not_formally_qualified"
)

_OPERATIONS = {"activation", "rollback", "bootstrap_first_pair"}
_ROLES = {"prior", "candidate", "baseline"}
_DATABASE_ORDER = ("comments", "research_workspace")
_DATABASE_FILES = {
    "comments": "comments.sqlite3",
    "research_workspace": "research_workspace.sqlite3",
}
_BUSINESS_FAMILIES = {
    "comments": "archive_comments",
    "research_workspace": "workspace_comments",
}
_RELEASE_PREFIX = "D:\\quant\\quant_platform\\releases\\"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_192_RE = re.compile(r"^[0-9a-f]{48}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_MAX_UINT64 = (1 << 64) - 1
_MAX_SQLITE_BYTES = (1 << 63) - 1


class ExactRuntimeCanaryEvidenceError(RuntimeError):
    """Canary request/result 不是 closed、canonical 或 exact-bound。"""


def _clone(value: object, *, label: str) -> dict[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except Exception as error:
        raise ExactRuntimeCanaryEvidenceError(
            f"{label} 不是 canonical JSON"
        ) from error
    if type(cloned) is not dict:
        raise ExactRuntimeCanaryEvidenceError(f"{label} 必须是 JSON object")
    return cloned


def _reject_nonfinite(value: str) -> object:
    raise ExactRuntimeCanaryEvidenceError(f"canary JSON 非有限数无效: {value}")


def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ExactRuntimeCanaryEvidenceError("canary JSON 存在重复或非字符串 key")
        result[key] = value
    return result


def _strict_json_bytes(raw: bytes, *, label: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise ExactRuntimeCanaryEvidenceError(f"{label} 必须是非空 bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_closed_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExactRuntimeCanaryEvidenceError(f"{label} 不是严格 UTF-8 JSON") from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise ExactRuntimeCanaryEvidenceError(f"{label} 不是 canonical object bytes")
    return value


def _closed(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ExactRuntimeCanaryEvidenceError(f"{label} schema 不闭合")
    return value


def _identifier(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _IDENTIFIER_RE.fullmatch(value) is None
        or value.endswith((".", " "))
    ):
        raise ExactRuntimeCanaryEvidenceError(f"{label} identifier 无效")
    return value


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise ExactRuntimeCanaryEvidenceError(f"{label} SHA-256 无效")
    return value


def _positive_int(
    value: object, *, label: str, maximum: int = _MAX_UINT64
) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        raise ExactRuntimeCanaryEvidenceError(f"{label} 正整数域无效")
    return value


def _nonnegative_int(
    value: object, *, label: str, maximum: int = _MAX_UINT64
) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ExactRuntimeCanaryEvidenceError(f"{label} 非负整数域无效")
    return value


def _self_hash(document: Mapping[str, object], field: str, *, label: str) -> str:
    claimed = _sha256(document[field], label=f"{label}.{field}")
    material = dict(document)
    material.pop(field)
    if identity_sha256(material) != claimed:
        raise ExactRuntimeCanaryEvidenceError(f"{label} self hash 不匹配")
    return claimed


def _release(value: object) -> dict[str, object]:
    release = _closed(
        value,
        {"release_id", "release_path", "manifest_sha256"},
        label="canary release",
    )
    release_id = _identifier(release["release_id"], label="release_id")
    if release["release_path"] != _RELEASE_PREFIX + release_id:
        raise ExactRuntimeCanaryEvidenceError(
            "canary release_path 不是 exact D release path"
        )
    _sha256(release["manifest_sha256"], label="release.manifest_sha256")
    return release


def _identity(document: Mapping[str, object]) -> None:
    attempt = _identifier(document["attempt_id"], label="attempt_id")
    del attempt
    _identifier(document["nonce"], label="nonce")
    _identifier(document["start_nonce"], label="start_nonce")
    operation = document["operation"]
    role = document["role"]
    if operation not in _OPERATIONS or role not in _ROLES:
        raise ExactRuntimeCanaryEvidenceError("canary operation/role 无效")
    if operation == "bootstrap_first_pair":
        valid_role = role == "baseline"
    else:
        valid_role = role in {"prior", "candidate"}
    if not valid_role:
        raise ExactRuntimeCanaryEvidenceError("canary role 与 operation 不匹配")
    for field in (
        "authorization_sha256",
        "scm_identity_sha256",
        "state_identity_sha256",
    ):
        _sha256(document[field], label=field)
    _release(document["release"])


def _expected_database_relative_path(
    *, attempt_id: str, nonce: str, role: str, database_name: str
) -> str:
    return (
        f"tmp/deployment-attempts/{attempt_id}-{nonce}/"
        f"runtime-canary/{role}/state/"
        f"{_DATABASE_FILES[database_name]}"
    )


def _request_database(
    value: object,
    *,
    attempt_id: str,
    nonce: str,
    role: str,
    expected_name: str,
) -> dict[str, object]:
    database = _closed(
        value,
        {
            "database_name",
            "relative_path",
            "source_seal_sha256",
            "isolated_copy_evidence_sha256",
            "compatibility_evidence_sha256",
            "initial_consistent_bytes",
            "initial_consistent_sha256",
            "request_database_sha256",
        },
        label=f"canary request database {expected_name}",
    )
    if database["database_name"] != expected_name:
        raise ExactRuntimeCanaryEvidenceError("canary request database 顺序或名称漂移")
    expected_path = _expected_database_relative_path(
        attempt_id=attempt_id,
        nonce=nonce,
        role=role,
        database_name=expected_name,
    )
    if database["relative_path"] != expected_path:
        raise ExactRuntimeCanaryEvidenceError("canary request database path 漂移")
    for field in (
        "source_seal_sha256",
        "isolated_copy_evidence_sha256",
        "compatibility_evidence_sha256",
        "initial_consistent_sha256",
    ):
        _sha256(database[field], label=f"{expected_name}.{field}")
    _positive_int(
        database["initial_consistent_bytes"],
        label=f"{expected_name}.initial_consistent_bytes",
        maximum=_MAX_SQLITE_BYTES,
    )
    _self_hash(
        database,
        "request_database_sha256",
        label=f"canary request database {expected_name}",
    )
    return database


def _database_order_hash(
    databases: list[dict[str, object]], *, hash_field: str
) -> str:
    return identity_sha256(
        [
            {
                "database_name": database["database_name"],
                hash_field: database[hash_field],
            }
            for database in databases
        ]
    )


def validate_exact_runtime_canary_request(value: object) -> dict[str, object]:
    request = _clone(value, label="exact runtime canary request")
    _closed(
        request,
        {
            "schema_version",
            "scope",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "start_nonce",
            "authorization_sha256",
            "scm_identity_sha256",
            "state_identity_sha256",
            "release",
            "databases",
            "database_order_sha256",
            "request_sha256",
        },
        label="exact runtime canary request",
    )
    if (
        request["schema_version"] != EXACT_RUNTIME_CANARY_REQUEST_SCHEMA
        or request["scope"] != EXACT_RUNTIME_CANARY_REQUEST_SCOPE
    ):
        raise ExactRuntimeCanaryEvidenceError("canary request 权限边界不同")
    _identity(request)
    values = request["databases"]
    if type(values) is not list or len(values) != len(_DATABASE_ORDER):
        raise ExactRuntimeCanaryEvidenceError("canary request 必须恰有两库")
    databases = [
        _request_database(
            value,
            attempt_id=str(request["attempt_id"]),
            nonce=str(request["nonce"]),
            role=str(request["role"]),
            expected_name=name,
        )
        for value, name in zip(values, _DATABASE_ORDER, strict=True)
    ]
    order_hash = _sha256(
        request["database_order_sha256"], label="database_order_sha256"
    )
    if order_hash != _database_order_hash(
        databases, hash_field="request_database_sha256"
    ):
        raise ExactRuntimeCanaryEvidenceError("canary request database order hash 不匹配")
    _self_hash(request, "request_sha256", label="exact runtime canary request")
    return request


def build_exact_runtime_canary_request(
    payload: Mapping[str, object],
) -> dict[str, object]:
    document = _clone(payload, label="canary request payload")
    forbidden = {
        "request_sha256",
        "database_order_sha256",
        "request_database_sha256",
    }
    if forbidden.intersection(document):
        raise ExactRuntimeCanaryEvidenceError("canary request payload 不得预置 hash")
    databases = document.get("databases")
    if type(databases) is not list:
        raise ExactRuntimeCanaryEvidenceError("canary request payload databases 无效")
    sealed: list[dict[str, object]] = []
    for value in databases:
        if type(value) is not dict or "request_database_sha256" in value:
            raise ExactRuntimeCanaryEvidenceError(
                "canary request database payload 不得预置 hash"
            )
        database = dict(value)
        database["request_database_sha256"] = identity_sha256(database)
        sealed.append(database)
    document["databases"] = sealed
    document["database_order_sha256"] = _database_order_hash(
        sealed, hash_field="request_database_sha256"
    )
    document["request_sha256"] = identity_sha256(document)
    return validate_exact_runtime_canary_request(document)


def _writer_lease_claim(value: object) -> dict[str, object]:
    claim = _closed(
        value,
        {
            "lease_id",
            "lease_nonce",
            "lease_epoch",
            "lease_record_sha256",
            "authority",
        },
        label="canary writer lease claim",
    )
    _identifier(claim["lease_id"], label="lease_id")
    if type(claim["lease_nonce"]) is not str or _NONCE_192_RE.fullmatch(
        claim["lease_nonce"]
    ) is None:
        raise ExactRuntimeCanaryEvidenceError("lease_nonce 无效")
    _positive_int(claim["lease_epoch"], label="lease_epoch")
    _sha256(claim["lease_record_sha256"], label="lease_record_sha256")
    if claim["authority"] != "claim_not_independently_observed":
        raise ExactRuntimeCanaryEvidenceError("writer lease claim 不得自授 authority")
    return claim


def _challenge(
    value: object,
    *,
    request_sha256: str,
    challenge_nonce: str,
    database_name: str,
) -> dict[str, object]:
    challenge = _closed(
        value,
        {
            "challenge_id",
            "insert_rowcount",
            "cas_applied_rowcount",
            "stale_cas_rowcount",
            "readback_revision",
            "append_only_event_count",
            "event_update_outcome",
            "event_delete_outcome",
            "challenge_sha256",
        },
        label=f"{database_name} SQL challenge",
    )
    expected_id = "canary-" + hashlib.sha256(
        f"{request_sha256}:{challenge_nonce}:{database_name}".encode("utf-8")
    ).hexdigest()[:32]
    if challenge["challenge_id"] != expected_id:
        raise ExactRuntimeCanaryEvidenceError("SQL challenge_id 未绑定 request/challenge")
    expected_numbers = {
        "insert_rowcount": 1,
        "cas_applied_rowcount": 1,
        "stale_cas_rowcount": 0,
        "readback_revision": 1,
        "append_only_event_count": 1,
    }
    for field, expected in expected_numbers.items():
        observed = _nonnegative_int(challenge[field], label=f"challenge.{field}")
        if observed != expected:
            raise ExactRuntimeCanaryEvidenceError(f"SQL challenge.{field} 结果无效")
    if (
        challenge["event_update_outcome"] != "rejected_by_trigger"
        or challenge["event_delete_outcome"] != "rejected_by_trigger"
    ):
        raise ExactRuntimeCanaryEvidenceError("SQL challenge append-only 结果无效")
    _self_hash(challenge, "challenge_sha256", label=f"{database_name} SQL challenge")
    return challenge


def _business_probe(value: object, *, database_name: str) -> dict[str, object]:
    probe = _closed(
        value,
        {
            "family",
            "create_rowcount",
            "idempotent_replay_rowcount",
            "edit_rowcount",
            "stale_edit_rowcount",
            "soft_delete_rowcount",
            "stale_delete_rowcount",
            "final_revision",
            "event_count",
            "receipt_count",
            "deleted_row_count",
            "business_probe_sha256",
        },
        label=f"{database_name} business probe",
    )
    if probe["family"] != _BUSINESS_FAMILIES[database_name]:
        raise ExactRuntimeCanaryEvidenceError("business probe family 漂移")
    expected_numbers = {
        "create_rowcount": 1,
        "idempotent_replay_rowcount": 0,
        "edit_rowcount": 1,
        "stale_edit_rowcount": 0,
        "soft_delete_rowcount": 1,
        "stale_delete_rowcount": 0,
        "final_revision": 3,
        "event_count": 3,
        "receipt_count": 3,
        "deleted_row_count": 1,
    }
    for field, expected in expected_numbers.items():
        observed = _nonnegative_int(probe[field], label=f"business_probe.{field}")
        if observed != expected:
            raise ExactRuntimeCanaryEvidenceError(f"business probe.{field} 结果无效")
    _self_hash(
        probe,
        "business_probe_sha256",
        label=f"{database_name} business probe",
    )
    return probe


def _result_database(
    value: object,
    *,
    request_database: Mapping[str, object],
    request_sha256: str,
    challenge_nonce: str,
) -> dict[str, object]:
    name = str(request_database["database_name"])
    database = _closed(
        value,
        {
            "database_name",
            "request_database_sha256",
            "initial_consistent_bytes",
            "initial_consistent_sha256",
            "initial_schema_sha256",
            "initial_business_summary_sha256",
            "challenge",
            "business_probe",
            "final_integrity_check",
            "final_quick_check",
            "final_foreign_key_violation_count",
            "final_schema_sha256",
            "final_business_summary_sha256",
            "final_consistent_bytes",
            "final_consistent_sha256",
            "final_members",
            "database_evidence_sha256",
        },
        label=f"canary result database {name}",
    )
    if (
        database["database_name"] != name
        or database["request_database_sha256"]
        != request_database["request_database_sha256"]
        or database["initial_consistent_bytes"]
        != request_database["initial_consistent_bytes"]
        or database["initial_consistent_sha256"]
        != request_database["initial_consistent_sha256"]
    ):
        raise ExactRuntimeCanaryEvidenceError("canary result 未绑定 request database")
    _positive_int(
        database["initial_consistent_bytes"],
        label=f"{name}.initial_consistent_bytes",
        maximum=_MAX_SQLITE_BYTES,
    )
    _positive_int(
        database["final_consistent_bytes"],
        label=f"{name}.final_consistent_bytes",
        maximum=_MAX_SQLITE_BYTES,
    )
    for field in (
        "initial_consistent_sha256",
        "initial_schema_sha256",
        "initial_business_summary_sha256",
        "final_schema_sha256",
        "final_business_summary_sha256",
        "final_consistent_sha256",
    ):
        _sha256(database[field], label=f"{name}.{field}")
    if (
        database["final_consistent_sha256"]
        == database["initial_consistent_sha256"]
        or database["final_business_summary_sha256"]
        == database["initial_business_summary_sha256"]
    ):
        raise ExactRuntimeCanaryEvidenceError("canary result 未证明业务持久写入")
    if (
        database["final_integrity_check"] != "ok"
        or database["final_quick_check"] != "ok"
        or _nonnegative_int(
            database["final_foreign_key_violation_count"],
            label=f"{name}.final_foreign_key_violation_count",
        )
        != 0
    ):
        raise ExactRuntimeCanaryEvidenceError("canary result SQLite 完整性失败")
    members = database["final_members"]
    if type(members) is not list or members != ["main"]:
        raise ExactRuntimeCanaryEvidenceError(
            "canary result SQLite 终态必须严格 main-only"
        )
    _challenge(
        database["challenge"],
        request_sha256=request_sha256,
        challenge_nonce=challenge_nonce,
        database_name=name,
    )
    _business_probe(database["business_probe"], database_name=name)
    _self_hash(
        database,
        "database_evidence_sha256",
        label=f"canary result database {name}",
    )
    return database


def _request_document(request: "ExactRuntimeCanaryRequest") -> dict[str, object]:
    if type(request) is not ExactRuntimeCanaryRequest:
        raise ExactRuntimeCanaryEvidenceError(
            "canary evidence 必须绑定 typed persistent request"
        )
    return validate_exact_runtime_canary_request(request.as_dict())


def validate_exact_runtime_canary_evidence(
    value: object, *, request: "ExactRuntimeCanaryRequest"
) -> dict[str, object]:
    request_document = _request_document(request)
    evidence = _clone(value, label="exact runtime canary evidence")
    _closed(
        evidence,
        {
            "schema_version",
            "scope",
            "request_sha256",
            "challenge_nonce",
            "attempt_id",
            "nonce",
            "operation",
            "role",
            "start_nonce",
            "authorization_sha256",
            "scm_identity_sha256",
            "state_identity_sha256",
            "release",
            "writer_lease_claim",
            "databases",
            "database_order_sha256",
            "result",
            "evidence_sha256",
        },
        label="exact runtime canary evidence",
    )
    if (
        evidence["schema_version"] != EXACT_RUNTIME_CANARY_EVIDENCE_SCHEMA
        or evidence["scope"] != EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE
        or evidence["result"] != EXACT_RUNTIME_CANARY_RESULT
    ):
        raise ExactRuntimeCanaryEvidenceError("canary evidence 权限边界不同")
    _identity(evidence)
    for field in (
        "attempt_id",
        "nonce",
        "operation",
        "role",
        "start_nonce",
        "authorization_sha256",
        "scm_identity_sha256",
        "state_identity_sha256",
        "release",
    ):
        if evidence[field] != request_document[field]:
            raise ExactRuntimeCanaryEvidenceError(
                f"canary evidence.{field} 未绑定 request"
            )
    if evidence["request_sha256"] != request_document["request_sha256"]:
        raise ExactRuntimeCanaryEvidenceError("canary evidence request hash 漂移")
    challenge_nonce = evidence["challenge_nonce"]
    if type(challenge_nonce) is not str or _NONCE_192_RE.fullmatch(challenge_nonce) is None:
        raise ExactRuntimeCanaryEvidenceError("canary challenge_nonce 无效")
    _writer_lease_claim(evidence["writer_lease_claim"])
    values = evidence["databases"]
    request_values = request_document["databases"]
    if type(values) is not list or len(values) != len(_DATABASE_ORDER):
        raise ExactRuntimeCanaryEvidenceError("canary evidence 必须恰有两库")
    databases = [
        _result_database(
            value,
            request_database=request_value,
            request_sha256=str(request_document["request_sha256"]),
            challenge_nonce=challenge_nonce,
        )
        for value, request_value in zip(values, request_values, strict=True)
    ]
    order_hash = _sha256(
        evidence["database_order_sha256"], label="database_order_sha256"
    )
    if order_hash != _database_order_hash(
        databases, hash_field="database_evidence_sha256"
    ):
        raise ExactRuntimeCanaryEvidenceError("canary evidence database order hash 不匹配")
    _self_hash(evidence, "evidence_sha256", label="exact runtime canary evidence")
    return evidence


def build_exact_runtime_canary_evidence(
    payload: Mapping[str, object], *, request: "ExactRuntimeCanaryRequest"
) -> dict[str, object]:
    request_document = _request_document(request)
    payload_document = _clone(payload, label="canary evidence payload")
    if {
        "evidence_sha256",
        "database_order_sha256",
        "database_evidence_sha256",
        "challenge_sha256",
        "business_probe_sha256",
    }.intersection(payload_document):
        raise ExactRuntimeCanaryEvidenceError("canary evidence payload 不得预置 hash")
    if set(payload_document) != {"challenge_nonce", "writer_lease_claim", "databases"}:
        raise ExactRuntimeCanaryEvidenceError("canary evidence payload schema 不闭合")
    values = payload_document["databases"]
    if type(values) is not list:
        raise ExactRuntimeCanaryEvidenceError("canary evidence payload databases 无效")
    sealed: list[dict[str, object]] = []
    for value in values:
        if type(value) is not dict or "database_evidence_sha256" in value:
            raise ExactRuntimeCanaryEvidenceError(
                "canary result database payload 不得预置 hash"
            )
        database = dict(value)
        challenge = database.get("challenge")
        probe = database.get("business_probe")
        if type(challenge) is not dict or "challenge_sha256" in challenge:
            raise ExactRuntimeCanaryEvidenceError("canary challenge payload 无效")
        if type(probe) is not dict or "business_probe_sha256" in probe:
            raise ExactRuntimeCanaryEvidenceError("business probe payload 无效")
        sealed_challenge = dict(challenge)
        sealed_challenge["challenge_sha256"] = identity_sha256(sealed_challenge)
        sealed_probe = dict(probe)
        sealed_probe["business_probe_sha256"] = identity_sha256(sealed_probe)
        database["challenge"] = sealed_challenge
        database["business_probe"] = sealed_probe
        database["database_evidence_sha256"] = identity_sha256(database)
        sealed.append(database)
    document: dict[str, object] = {
        "schema_version": EXACT_RUNTIME_CANARY_EVIDENCE_SCHEMA,
        "scope": EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE,
        "request_sha256": request_document["request_sha256"],
        "challenge_nonce": payload_document["challenge_nonce"],
        "attempt_id": request_document["attempt_id"],
        "nonce": request_document["nonce"],
        "operation": request_document["operation"],
        "role": request_document["role"],
        "start_nonce": request_document["start_nonce"],
        "authorization_sha256": request_document["authorization_sha256"],
        "scm_identity_sha256": request_document["scm_identity_sha256"],
        "state_identity_sha256": request_document["state_identity_sha256"],
        "release": request_document["release"],
        "writer_lease_claim": payload_document["writer_lease_claim"],
        "databases": sealed,
        "database_order_sha256": _database_order_hash(
            sealed, hash_field="database_evidence_sha256"
        ),
        "result": EXACT_RUNTIME_CANARY_RESULT,
    }
    document["evidence_sha256"] = identity_sha256(document)
    return validate_exact_runtime_canary_evidence(document, request=request)


@dataclass(frozen=True, slots=True)
class ExactRuntimeCanaryRequest:
    _raw: bytes

    @classmethod
    def from_document(cls, value: object) -> "ExactRuntimeCanaryRequest":
        return cls(canonical_bytes(validate_exact_runtime_canary_request(value)))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise ExactRuntimeCanaryEvidenceError("已验证 canary request 类型漂移")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def request_sha256(self) -> str:
        return str(self.as_dict()["request_sha256"])


@dataclass(frozen=True, slots=True)
class ExactRuntimeCanaryEvidence:
    _raw: bytes

    @classmethod
    def from_document(
        cls, value: object, *, request: ExactRuntimeCanaryRequest
    ) -> "ExactRuntimeCanaryEvidence":
        return cls(
            canonical_bytes(
                validate_exact_runtime_canary_evidence(value, request=request)
            )
        )

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise ExactRuntimeCanaryEvidenceError("已验证 canary evidence 类型漂移")
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


def parse_exact_runtime_canary_request_bytes(raw: bytes) -> ExactRuntimeCanaryRequest:
    return ExactRuntimeCanaryRequest.from_document(
        _strict_json_bytes(raw, label="exact runtime canary request")
    )


def parse_exact_runtime_canary_evidence_bytes(
    raw: bytes, *, request: ExactRuntimeCanaryRequest
) -> ExactRuntimeCanaryEvidence:
    return ExactRuntimeCanaryEvidence.from_document(
        _strict_json_bytes(raw, label="exact runtime canary evidence"),
        request=request,
    )


__all__ = [
    "EXACT_RUNTIME_CANARY_EVIDENCE_SCHEMA",
    "EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE",
    "EXACT_RUNTIME_CANARY_REQUEST_SCHEMA",
    "EXACT_RUNTIME_CANARY_REQUEST_SCOPE",
    "EXACT_RUNTIME_CANARY_RESULT",
    "ExactRuntimeCanaryEvidence",
    "ExactRuntimeCanaryEvidenceError",
    "ExactRuntimeCanaryRequest",
    "build_exact_runtime_canary_evidence",
    "build_exact_runtime_canary_request",
    "parse_exact_runtime_canary_evidence_bytes",
    "parse_exact_runtime_canary_request_bytes",
    "validate_exact_runtime_canary_evidence",
    "validate_exact_runtime_canary_request",
]
