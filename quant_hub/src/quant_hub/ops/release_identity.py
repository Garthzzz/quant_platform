"""Release/checkpoint/recovery 的无环身份合同。

该模块只定义不可变对象的 schema、canonical hash 和引用图校验，不执行部署、
切换或数据库备份。唯一允许的依赖方向是::

    active -> release (R)
    checkpoint (C) -> captured-under release
    recovery manifest (RM) -> release + checkpoint
    receipt -> release/recovery/checkpoint/result

receipt 是 append-only 证据，永远不能作为 active authority。动态 state-only
checkpoint 也不得改变 release manifest 或 active pointer。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import PureWindowsPath
import re
from typing import Iterable, Mapping, Sequence


RELEASE_SCHEMA = "qrh-release-manifest/v1"
ACTIVE_SCHEMA = "qrh-active-release/v1"
CHECKPOINT_SCHEMA = "qrh-checkpoint-manifest/v1"
RECOVERY_SCHEMA = "qrh-recovery-manifest/v1"

RECEIPT_SCHEMAS = {
    "qrh-recovery-protection-receipt/v1": "recovery_protection",
    "qrh-activation-receipt/v1": "activation",
    "qrh-failure-receipt/v1": "failure",
    "qrh-recovery-receipt/v1": "recovery",
    "qrh-checkpoint-receipt/v1": "checkpoint",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_RELEASE_DYNAMIC_REFERENCE_RE = re.compile(
    r"(?:^|_)(?:recovery_manifest|checkpoint(?:_manifest)?|recovery_bundle|bundle)"
    r"_(?:id|sha256|hash|time|timestamp|captured_at|created_at|path|uri)$"
)
_RELEASE_DYNAMIC_REFERENCE_KEYS = {
    "recovery_manifest",
    "checkpoint",
    "checkpoint_manifest",
    "recovery_bundle",
    "bundle",
}
_RELEASE_SELF_REFERENCE_KEYS = {
    "release_manifest",
    "release_manifest_sha256",
    "release_manifest_hash",
    "manifest_sha256",
    "self_sha256",
}
_RECEIPT_AUTHORITY_KEYS = {
    "active_authority",
    "active_pointer",
    "active_release",
    "active_release_json",
    "active_manifest_sha256",
    "current",
    "current_release",
    "current_manifest_sha256",
    "is_active_authority",
    "release_path",
}


class IdentityContractError(ValueError):
    """身份 schema、引用或状态转换不符合 fail-closed 合同。"""


@dataclass(frozen=True)
class IdentityGraphReport:
    """成功校验后的机器可读依赖图摘要。"""

    active_manifest_sha256: str
    release_count: int
    checkpoint_count: int
    recovery_manifest_count: int
    receipt_count: int
    edges: tuple[tuple[str, str], ...]


def canonical_manifest_bytes(value: object) -> bytes:
    """以稳定 JSON 编码 manifest；拒绝 NaN/Infinity 和非 JSON 对象。"""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise IdentityContractError(f"manifest is not canonical JSON: {error}") from error
    return rendered.encode("utf-8")


def manifest_sha256(value: object) -> str:
    return hashlib.sha256(canonical_manifest_bytes(value)).hexdigest()


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise IdentityContractError(f"{label} must be a JSON object with string keys")
    return value


def _required(mapping: Mapping[str, object], fields: Iterable[str], *, label: str) -> None:
    missing = sorted(set(fields) - set(mapping))
    if missing:
        raise IdentityContractError(f"{label} missing required fields: {missing}")


def _exact_fields(
    mapping: Mapping[str, object], fields: Iterable[str], *, label: str
) -> None:
    expected = set(fields)
    _required(mapping, expected, label=label)
    extra = sorted(set(mapping) - expected)
    if extra:
        raise IdentityContractError(f"{label} contains forbidden fields: {extra}")


def _text(value: object, *, label: str, max_length: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or _CONTROL_RE.search(value)
    ):
        raise IdentityContractError(f"{label} must be non-empty control-free text")
    return value


def _identifier(value: object, *, label: str) -> str:
    result = _text(value, label=label, max_length=255)
    if any(part in result for part in ("/", "\\", "..")):
        raise IdentityContractError(f"{label} is not a stable identifier")
    return result


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise IdentityContractError(f"{label} must be lowercase SHA-256 hex")
    return value


def _timestamp(value: object, *, label: str) -> str:
    rendered = _text(value, label=label, max_length=64)
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError as error:
        raise IdentityContractError(f"{label} must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IdentityContractError(f"{label} must include a timezone")
    return rendered


def _parsed_timestamp(value: object, *, label: str) -> datetime:
    rendered = _timestamp(value, label=label)
    return datetime.fromisoformat(rendered.replace("Z", "+00:00"))


def _nonnegative_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IdentityContractError(f"{label} must be a non-negative integer")
    return value


def _walk(mapping: Mapping[str, object], path: tuple[str, ...] = ()):
    for key, value in mapping.items():
        current = (*path, key)
        yield current, key, value
        if isinstance(value, dict):
            yield from _walk(value, current)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    yield from _walk(item, (*current, str(index)))


def _validate_named_hashes(mapping: Mapping[str, object], *, label: str) -> None:
    for path, key, value in _walk(mapping):
        if key.lower().endswith("_sha256"):
            _sha256(value, label=f"{label}.{'.'.join(path)}")


def _validate_bool_fields(
    value: object, expected_fields: Sequence[str], *, label: str, expected: bool
) -> None:
    mapping = _mapping(value, label=label)
    _exact_fields(mapping, expected_fields, label=label)
    failed = [field for field in expected_fields if mapping[field] is not expected]
    if failed:
        raise IdentityContractError(
            f"{label} requires {expected!r} for all gates; failed: {failed}"
        )


def validate_release_manifest(value: object) -> Mapping[str, object]:
    """校验 immutable R，并拒绝任何具体 RM/C/bundle 身份反向引用。"""

    release = _mapping(value, label="release_manifest")
    _required(
        release,
        (
            "schema_version",
            "release_id",
            "built_at",
            "application",
            "content",
            "resources",
            "state",
            "recovery",
        ),
        label="release_manifest",
    )
    if release["schema_version"] != RELEASE_SCHEMA:
        raise IdentityContractError("release_manifest has unsupported schema_version")
    _identifier(release["release_id"], label="release_manifest.release_id")
    _timestamp(release["built_at"], label="release_manifest.built_at")

    application = _mapping(release["application"], label="release_manifest.application")
    _required(
        application,
        ("commit_sha", "tracked_tree_sha256", "build_tool_version"),
        label="release_manifest.application",
    )
    if not isinstance(application["commit_sha"], str) or not _COMMIT_RE.fullmatch(
        application["commit_sha"]
    ):
        raise IdentityContractError("release_manifest.application.commit_sha is invalid")
    source_kind = application.get("source_kind", "git")
    if source_kind == "git":
        if application["commit_sha"] == "0" * 40:
            raise IdentityContractError("Git release cannot use the legacy zero commit sentinel")
        if "source_archive_sha256" in application or "legacy_deployment_id" in application:
            raise IdentityContractError("Git release cannot claim legacy broadcast provenance")
    elif source_kind == "legacy_broadcast":
        if application["commit_sha"] != "0" * 40:
            raise IdentityContractError(
                "legacy broadcast must use the explicit zero commit sentinel"
            )
        _sha256(
            application.get("source_archive_sha256"),
            label="release_manifest.application.source_archive_sha256",
        )
        _identifier(
            application.get("legacy_deployment_id"),
            label="release_manifest.application.legacy_deployment_id",
        )
    else:
        raise IdentityContractError("release_manifest.application.source_kind is invalid")
    _text(
        application["build_tool_version"],
        label="release_manifest.application.build_tool_version",
    )

    content = _mapping(release["content"], label="release_manifest.content")
    _required(
        content,
        (
            "snapshot_id",
            "source_inventory_sha256",
            "ir_sha256",
            "knowledge_sha256",
            "search_sha256",
            "knowledge_enrichment",
        ),
        label="release_manifest.content",
    )
    _identifier(content["snapshot_id"], label="release_manifest.content.snapshot_id")
    _mapping(
        content["knowledge_enrichment"],
        label="release_manifest.content.knowledge_enrichment",
    )

    resources = _mapping(release["resources"], label="release_manifest.resources")
    _required(resources, ("inventory_sha256",), label="release_manifest.resources")
    state = _mapping(release["state"], label="release_manifest.state")
    _required(state, ("compatibility",), label="release_manifest.state")
    _mapping(state["compatibility"], label="release_manifest.state.compatibility")
    recovery = _mapping(release["recovery"], label="release_manifest.recovery")
    _required(recovery, ("compatibility",), label="release_manifest.recovery")
    _mapping(
        recovery["compatibility"], label="release_manifest.recovery.compatibility"
    )

    for path, key, _ in _walk(release):
        normalized = key.casefold().replace("-", "_")
        self_reference = normalized in _RELEASE_SELF_REFERENCE_KEYS and (
            len(path) == 1
            or normalized.startswith("release_manifest")
            or normalized == "self_sha256"
        )
        if (
            normalized in _RELEASE_DYNAMIC_REFERENCE_KEYS
            or self_reference
            or _RELEASE_DYNAMIC_REFERENCE_RE.search(normalized)
            or normalized in _RECEIPT_AUTHORITY_KEYS
            or normalized.endswith("_receipt")
            or any(
                marker in normalized
                for marker in (
                    "activation_receipt_",
                    "failure_receipt_",
                    "recovery_receipt_",
                    "recovery_protection_receipt_",
                    "checkpoint_receipt_",
                )
            )
        ):
            raise IdentityContractError(
                "release_manifest contains dynamic recovery/checkpoint/receipt "
                f"identity at {'.'.join(path)}"
            )
    _validate_named_hashes(release, label="release_manifest")
    canonical_manifest_bytes(release)
    return release


def validate_active_release(value: object) -> Mapping[str, object]:
    """校验唯一 active pointer；不允许 receipt/RM/C 字段混入。"""

    active = _mapping(value, label="active_release")
    _exact_fields(
        active,
        ("schema_version", "release_id", "release_path", "manifest_sha256"),
        label="active_release",
    )
    if active["schema_version"] != ACTIVE_SCHEMA:
        raise IdentityContractError("active_release has unsupported schema_version")
    release_id = _identifier(active["release_id"], label="active_release.release_id")
    release_path = _text(active["release_path"], label="active_release.release_path")
    windows_path = PureWindowsPath(release_path)
    if not windows_path.is_absolute() or ".." in windows_path.parts:
        raise IdentityContractError("active_release.release_path must be absolute and closed")
    if windows_path.name.casefold() != release_id.casefold():
        raise IdentityContractError("active_release.release_path must end in release_id")
    _sha256(active["manifest_sha256"], label="active_release.manifest_sha256")
    canonical_manifest_bytes(active)
    return active


def validate_checkpoint_manifest(value: object) -> Mapping[str, object]:
    checkpoint = _mapping(value, label="checkpoint_manifest")
    _exact_fields(
        checkpoint,
        (
            "schema_version",
            "checkpoint_id",
            "captured_at",
            "captured_under_active_release",
            "state",
            "verification",
        ),
        label="checkpoint_manifest",
    )
    if checkpoint["schema_version"] != CHECKPOINT_SCHEMA:
        raise IdentityContractError("checkpoint_manifest has unsupported schema_version")
    _identifier(checkpoint["checkpoint_id"], label="checkpoint_manifest.checkpoint_id")
    _timestamp(checkpoint["captured_at"], label="checkpoint_manifest.captured_at")
    release = _mapping(
        checkpoint["captured_under_active_release"],
        label="checkpoint_manifest.captured_under_active_release",
    )
    _exact_fields(
        release,
        ("release_id", "manifest_sha256"),
        label="checkpoint_manifest.captured_under_active_release",
    )
    _identifier(release["release_id"], label="checkpoint captured release_id")
    _sha256(release["manifest_sha256"], label="checkpoint captured manifest_sha256")
    state = _mapping(checkpoint["state"], label="checkpoint_manifest.state")
    _required(
        state,
        ("authority_id", "inventory_sha256", "database_count"),
        label="checkpoint_manifest.state",
    )
    _identifier(state["authority_id"], label="checkpoint_manifest.state.authority_id")
    _nonnegative_int(
        state["database_count"], label="checkpoint_manifest.state.database_count"
    )
    _validate_bool_fields(
        checkpoint["verification"],
        ("integrity", "foreign_keys", "restorable"),
        label="checkpoint_manifest.verification",
        expected=True,
    )
    for path, key, _ in _walk(checkpoint):
        normalized = key.casefold().replace("-", "_")
        # ``logical_counts`` is a data map keyed by real SQLite table names,
        # not a manifest schema namespace.  A legitimate table such as
        # ``command_receipt`` cannot create an identity edge because its value
        # is only a non-negative row count.  Contract-owned keys remain strict.
        user_table_count_key = (
            len(path) == 5
            and path[0] == "state"
            and path[1] == "databases"
            and path[2].isdigit()
            and path[3] == "logical_counts"
        )
        if (
            not user_table_count_key
            and (
                "recovery_manifest" in normalized
                or normalized.endswith("_receipt")
                or normalized in _RECEIPT_AUTHORITY_KEYS
            )
        ):
            raise IdentityContractError(
                f"checkpoint_manifest contains forbidden back-reference at {'.'.join(path)}"
            )
    _validate_named_hashes(checkpoint, label="checkpoint_manifest")
    canonical_manifest_bytes(checkpoint)
    return checkpoint


def validate_recovery_manifest(value: object) -> Mapping[str, object]:
    recovery = _mapping(value, label="recovery_manifest")
    _exact_fields(
        recovery,
        (
            "schema_version",
            "bundle_id",
            "created_at",
            "release",
            "checkpoint",
            "closure",
            "compatibility",
            "restore",
            "no_secret_attestation",
        ),
        label="recovery_manifest",
    )
    if recovery["schema_version"] != RECOVERY_SCHEMA:
        raise IdentityContractError("recovery_manifest has unsupported schema_version")
    _identifier(recovery["bundle_id"], label="recovery_manifest.bundle_id")
    _timestamp(recovery["created_at"], label="recovery_manifest.created_at")
    release = _mapping(recovery["release"], label="recovery_manifest.release")
    _exact_fields(
        release,
        ("release_id", "manifest_sha256"),
        label="recovery_manifest.release",
    )
    _identifier(release["release_id"], label="recovery_manifest.release.release_id")
    checkpoint = _mapping(
        recovery["checkpoint"], label="recovery_manifest.checkpoint"
    )
    _exact_fields(
        checkpoint,
        ("checkpoint_id", "manifest_sha256"),
        label="recovery_manifest.checkpoint",
    )
    _identifier(
        checkpoint["checkpoint_id"],
        label="recovery_manifest.checkpoint.checkpoint_id",
    )
    closure = _mapping(recovery["closure"], label="recovery_manifest.closure")
    _exact_fields(
        closure,
        ("inventory_sha256", "file_count", "total_bytes"),
        label="recovery_manifest.closure",
    )
    _nonnegative_int(closure["file_count"], label="recovery closure file_count")
    _nonnegative_int(closure["total_bytes"], label="recovery closure total_bytes")
    compatibility = _mapping(
        recovery["compatibility"], label="recovery_manifest.compatibility"
    )
    _required(compatibility, ("verdict",), label="recovery_manifest.compatibility")
    if compatibility["verdict"] != "compatible":
        raise IdentityContractError("recovery manifest is not state/release compatible")
    restore = _mapping(recovery["restore"], label="recovery_manifest.restore")
    _required(
        restore,
        ("protocol_version", "tool_inventory_sha256", "runbook_sha256"),
        label="recovery_manifest.restore",
    )
    _text(restore["protocol_version"], label="recovery restore protocol_version")
    attestation = _mapping(
        recovery["no_secret_attestation"],
        label="recovery_manifest.no_secret_attestation",
    )
    _required(attestation, ("verdict", "scanner_version"), label="no-secret attestation")
    if attestation["verdict"] != "pass":
        raise IdentityContractError("recovery manifest no-secret attestation did not pass")
    _text(attestation["scanner_version"], label="no-secret scanner_version")
    for path, key, _ in _walk(recovery):
        normalized = key.casefold().replace("-", "_")
        if (
            normalized.endswith("_receipt")
            or normalized in _RECEIPT_AUTHORITY_KEYS
            or normalized == "recovery_manifest"
        ):
            raise IdentityContractError(
                f"recovery_manifest contains forbidden authority edge at {'.'.join(path)}"
            )
    _validate_named_hashes(recovery, label="recovery_manifest")
    canonical_manifest_bytes(recovery)
    return recovery


def _receipt_common(receipt: Mapping[str, object]) -> str:
    schema = receipt.get("schema_version")
    receipt_type = RECEIPT_SCHEMAS.get(schema) if isinstance(schema, str) else None
    if receipt_type is None:
        raise IdentityContractError("receipt has unsupported schema_version")
    if receipt.get("receipt_type") != receipt_type:
        raise IdentityContractError("receipt_type does not match schema_version")
    _identifier(receipt.get("receipt_id"), label="receipt.receipt_id")
    _timestamp(receipt.get("recorded_at"), label="receipt.recorded_at")
    if receipt.get("authority") != "evidence_only":
        raise IdentityContractError("receipt authority must be evidence_only")
    for path, key, _ in _walk(receipt):
        normalized = key.casefold().replace("-", "_")
        if normalized in _RECEIPT_AUTHORITY_KEYS:
            raise IdentityContractError(
                f"receipt cannot define active authority at {'.'.join(path)}"
            )
    return receipt_type


def validate_receipt(value: object) -> Mapping[str, object]:
    """校验五类 append-only receipt；它们都不具有 active authority。"""

    receipt = _mapping(value, label="receipt")
    receipt_type = _receipt_common(receipt)
    common = {"schema_version", "receipt_type", "receipt_id", "recorded_at", "authority"}
    triple = {
        "release_manifest_sha256",
        "recovery_manifest_sha256",
        "checkpoint_manifest_sha256",
    }
    if receipt_type == "recovery_protection":
        _exact_fields(
            receipt,
            common
            | triple
            | {"deployment_attempt_id", "verdict", "pre_activation_verification"},
            label="recovery_protection_receipt",
        )
        _identifier(
            receipt["deployment_attempt_id"], label="receipt.deployment_attempt_id"
        )
        if receipt["verdict"] != "protected":
            raise IdentityContractError("recovery protection verdict must be protected")
        verification = _mapping(
            receipt["pre_activation_verification"],
            label="receipt.pre_activation_verification",
        )
        _exact_fields(
            verification,
            ("closure", "compatibility", "failure_domain", "no_secret", "active_pointer_switched"),
            label="receipt.pre_activation_verification",
        )
        _validate_bool_fields(
            {key: verification[key] for key in ("closure", "compatibility", "failure_domain", "no_secret")},
            ("closure", "compatibility", "failure_domain", "no_secret"),
            label="receipt.pre_activation_verification.gates",
            expected=True,
        )
        if verification["active_pointer_switched"] is not False:
            raise IdentityContractError(
                "recovery protection receipt must be recorded before active switch"
            )
    elif receipt_type == "activation":
        _exact_fields(
            receipt,
            common
            | triple
            | {
                "deployment_attempt_id",
                "verdict",
                "switch",
                "post_activation_verification",
            },
            label="activation_receipt",
        )
        _identifier(
            receipt["deployment_attempt_id"], label="receipt.deployment_attempt_id"
        )
        if receipt["verdict"] != "activated":
            raise IdentityContractError("activation verdict must be activated")
        _validate_bool_fields(
            receipt["switch"],
            ("active_pointer_switched", "candidate_started"),
            label="receipt.switch",
            expected=True,
        )
        _validate_bool_fields(
            receipt["post_activation_verification"],
            ("health", "critical_functions", "writer_fence"),
            label="receipt.post_activation_verification",
            expected=True,
        )
    elif receipt_type == "failure":
        _exact_fields(
            receipt,
            common
            | {
                "deployment_attempt_id",
                "candidate_manifest_sha256",
                "prior_manifest_sha256",
                "verdict",
                "failed_phase",
                "error_code",
                "rollback",
            },
            label="failure_receipt",
        )
        _identifier(
            receipt["deployment_attempt_id"], label="receipt.deployment_attempt_id"
        )
        if receipt["verdict"] != "failed":
            raise IdentityContractError("failure receipt verdict must be failed")
        _text(receipt["failed_phase"], label="failure receipt failed_phase")
        _text(receipt["error_code"], label="failure receipt error_code")
        rollback = _mapping(receipt["rollback"], label="failure receipt rollback")
        _exact_fields(rollback, ("attempted", "succeeded"), label="failure receipt rollback")
        if not isinstance(rollback["attempted"], bool) or not isinstance(
            rollback["succeeded"], bool
        ):
            raise IdentityContractError("failure receipt rollback flags must be boolean")
        if rollback["succeeded"] and not rollback["attempted"]:
            raise IdentityContractError("rollback cannot succeed unless attempted")
    elif receipt_type == "recovery":
        _exact_fields(
            receipt,
            common
            | triple
            | {"recovery_attempt_id", "verdict", "restore_verification"},
            label="recovery_receipt",
        )
        _identifier(receipt["recovery_attempt_id"], label="receipt.recovery_attempt_id")
        if receipt["verdict"] != "recovered":
            raise IdentityContractError("recovery receipt verdict must be recovered")
        _validate_bool_fields(
            receipt["restore_verification"],
            ("closure", "state_restored", "service_started", "post_restore"),
            label="receipt.restore_verification",
            expected=True,
        )
    else:
        _exact_fields(
            receipt,
            common
            | triple
            | {
                "backup_attempt_id",
                "operation",
                "verdict",
                "state_only_verification",
            },
            label="checkpoint_receipt",
        )
        _identifier(receipt["backup_attempt_id"], label="receipt.backup_attempt_id")
        if receipt["operation"] != "state_only_backup":
            raise IdentityContractError(
                "checkpoint receipt operation must be state_only_backup"
            )
        if receipt["verdict"] != "checkpoint_verified":
            raise IdentityContractError(
                "checkpoint receipt verdict must be checkpoint_verified"
            )
        _validate_bool_fields(
            receipt["state_only_verification"],
            ("integrity", "closure", "release_unchanged", "active_unchanged"),
            label="receipt.state_only_verification",
            expected=True,
        )
    _validate_named_hashes(receipt, label="receipt")
    canonical_manifest_bytes(receipt)
    return receipt


def authorize_receipt_append(
    value: object,
    *,
    observed_active_release: object | None = None,
    existing_receipts: Sequence[object] = (),
) -> Mapping[str, object]:
    """在 append 前执行阶段门禁，尤其防止伪造成功 activation。

    历史 receipt 的离线 graph lint 不要求它仍等于当前 active；但写入新的成功
    activation receipt 时，必须提供刚验证的 active pointer 且其 manifest hash
    与 receipt 一致。相同 deployment attempt 不能同时存在 activation/failure。
    """

    receipt = validate_receipt(value)
    receipt_type = str(receipt["receipt_type"])
    validated_existing = [validate_receipt(existing) for existing in existing_receipts]
    if receipt_type == "activation":
        if observed_active_release is None:
            raise IdentityContractError(
                "activation receipt append requires observed post-switch active authority"
            )
        active = validate_active_release(observed_active_release)
        if active["manifest_sha256"] != receipt["release_manifest_sha256"]:
            raise IdentityContractError(
                "activation receipt release does not match observed active authority"
            )
        protections = [
            existing
            for existing in validated_existing
            if existing.get("deployment_attempt_id")
            == receipt["deployment_attempt_id"]
            and existing["receipt_type"] == "recovery_protection"
        ]
        if len(protections) != 1:
            raise IdentityContractError(
                "activation receipt requires exactly one prior recovery protection receipt"
            )
        protection = protections[0]
        for field in (
            "release_manifest_sha256",
            "recovery_manifest_sha256",
            "checkpoint_manifest_sha256",
        ):
            if protection[field] != receipt[field]:
                raise IdentityContractError(
                    "activation receipt does not match prior protected R/RM/C closure"
                )
        if _parsed_timestamp(
            protection["recorded_at"], label="protection recorded_at"
        ) >= _parsed_timestamp(receipt["recorded_at"], label="activation recorded_at"):
            raise IdentityContractError(
                "activation receipt must follow its recovery protection receipt"
            )
    elif receipt_type == "checkpoint":
        if observed_active_release is None:
            raise IdentityContractError(
                "checkpoint receipt append requires observed unchanged active authority"
            )
        active = validate_active_release(observed_active_release)
        if active["manifest_sha256"] != receipt["release_manifest_sha256"]:
            raise IdentityContractError(
                "checkpoint receipt release does not match observed active authority"
            )

    attempt_id = receipt.get("deployment_attempt_id")
    if attempt_id is not None:
        terminal_types: set[str] = set()
        for candidate in validated_existing:
            if candidate.get("deployment_attempt_id") != attempt_id:
                continue
            if candidate["receipt_type"] in {"activation", "failure"}:
                terminal_types.add(str(candidate["receipt_type"]))
        if receipt_type in {"activation", "failure"} and terminal_types:
            raise IdentityContractError(
                "deployment attempt already has a terminal activation/failure receipt"
            )
    return receipt


def _index_by_hash(
    values: Sequence[object],
    validator,
    *,
    id_field: str,
    label: str,
) -> tuple[dict[str, Mapping[str, object]], dict[str, str]]:
    by_hash: dict[str, Mapping[str, object]] = {}
    id_to_hash: dict[str, str] = {}
    for value in values:
        item = validator(value)
        digest = manifest_sha256(item)
        identifier = str(item[id_field])
        previous = id_to_hash.get(identifier)
        if previous is not None and previous != digest:
            raise IdentityContractError(
                f"{label} stable ID {identifier!r} resolves to multiple immutable hashes"
            )
        id_to_hash[identifier] = digest
        by_hash[digest] = item
    return by_hash, id_to_hash


def _ensure_dependency(
    digest: object,
    index: Mapping[str, Mapping[str, object]],
    *,
    label: str,
) -> str:
    checked = _sha256(digest, label=label)
    if checked not in index:
        raise IdentityContractError(f"{label} does not resolve to a supplied immutable object")
    return checked


def _assert_acyclic(edges: Sequence[tuple[str, str]]) -> None:
    adjacency: dict[str, list[str]] = {}
    for source, target in edges:
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise IdentityContractError(f"identity dependency graph contains a cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for target in adjacency[node]:
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(adjacency):
        visit(node)


def lint_identity_graph(
    *,
    active_release: object,
    release_manifests: Sequence[object],
    checkpoint_manifests: Sequence[object] = (),
    recovery_manifests: Sequence[object] = (),
    receipts: Sequence[object] = (),
) -> IdentityGraphReport:
    """解析所有 hash edge，拒绝悬空、反向、终态冲突和循环依赖。"""

    releases, release_ids = _index_by_hash(
        release_manifests,
        validate_release_manifest,
        id_field="release_id",
        label="release",
    )
    checkpoints, checkpoint_ids = _index_by_hash(
        checkpoint_manifests,
        validate_checkpoint_manifest,
        id_field="checkpoint_id",
        label="checkpoint",
    )
    recoveries, _ = _index_by_hash(
        recovery_manifests,
        validate_recovery_manifest,
        id_field="bundle_id",
        label="recovery manifest",
    )
    active = validate_active_release(active_release)
    active_hash = _ensure_dependency(
        active["manifest_sha256"], releases, label="active_release.manifest_sha256"
    )
    if release_ids.get(str(active["release_id"])) != active_hash:
        raise IdentityContractError("active release_id and manifest hash disagree")

    edges: list[tuple[str, str]] = [("active", f"R:{active_hash}")]
    for digest, checkpoint in checkpoints.items():
        captured = _mapping(
            checkpoint["captured_under_active_release"], label="checkpoint captured release"
        )
        release_hash = _ensure_dependency(
            captured["manifest_sha256"], releases, label="checkpoint captured release hash"
        )
        if release_ids.get(str(captured["release_id"])) != release_hash:
            raise IdentityContractError("checkpoint captured release ID/hash disagree")
        edges.append((f"C:{digest}", f"R:{release_hash}"))

    for digest, recovery in recoveries.items():
        release_ref = _mapping(recovery["release"], label="recovery release")
        checkpoint_ref = _mapping(recovery["checkpoint"], label="recovery checkpoint")
        release_hash = _ensure_dependency(
            release_ref["manifest_sha256"], releases, label="recovery release hash"
        )
        checkpoint_hash = _ensure_dependency(
            checkpoint_ref["manifest_sha256"],
            checkpoints,
            label="recovery checkpoint hash",
        )
        if release_ids.get(str(release_ref["release_id"])) != release_hash:
            raise IdentityContractError("recovery release ID/hash disagree")
        if checkpoint_ids.get(str(checkpoint_ref["checkpoint_id"])) != checkpoint_hash:
            raise IdentityContractError("recovery checkpoint ID/hash disagree")
        edges.extend(
            (
                (f"RM:{digest}", f"R:{release_hash}"),
                (f"RM:{digest}", f"C:{checkpoint_hash}"),
            )
        )

    terminal_attempts: dict[str, str] = {}
    protection_attempts: dict[str, Mapping[str, object]] = {}
    activation_attempts: dict[str, Mapping[str, object]] = {}
    receipt_ids: dict[str, str] = {}
    for value in receipts:
        receipt = validate_receipt(value)
        digest = manifest_sha256(receipt)
        receipt_id = str(receipt["receipt_id"])
        previous = receipt_ids.get(receipt_id)
        if previous is not None and previous != digest:
            raise IdentityContractError("receipt_id resolves to multiple immutable hashes")
        receipt_ids[receipt_id] = digest
        node = f"receipt:{digest}"
        receipt_type = str(receipt["receipt_type"])
        if receipt_type in {
            "recovery_protection",
            "activation",
            "recovery",
            "checkpoint",
        }:
            release_hash = _ensure_dependency(
                receipt["release_manifest_sha256"], releases, label="receipt release hash"
            )
            recovery_hash = _ensure_dependency(
                receipt["recovery_manifest_sha256"],
                recoveries,
                label="receipt recovery hash",
            )
            checkpoint_hash = _ensure_dependency(
                receipt["checkpoint_manifest_sha256"],
                checkpoints,
                label="receipt checkpoint hash",
            )
            recovery = recoveries[recovery_hash]
            if (
                _mapping(recovery["release"], label="recovery release")["manifest_sha256"]
                != release_hash
                or _mapping(recovery["checkpoint"], label="recovery checkpoint")[
                    "manifest_sha256"
                ]
                != checkpoint_hash
            ):
                raise IdentityContractError("receipt R/RM/C closure is inconsistent")
            edges.extend(
                (
                    (node, f"R:{release_hash}"),
                    (node, f"RM:{recovery_hash}"),
                    (node, f"C:{checkpoint_hash}"),
                )
            )
        else:
            candidate_hash = _ensure_dependency(
                receipt["candidate_manifest_sha256"],
                releases,
                label="failure candidate hash",
            )
            prior_hash = _ensure_dependency(
                receipt["prior_manifest_sha256"], releases, label="failure prior hash"
            )
            edges.extend(
                ((node, f"R:{candidate_hash}"), (node, f"R:{prior_hash}"))
            )

        if receipt_type in {"activation", "failure"}:
            attempt_id = str(receipt["deployment_attempt_id"])
            previous_terminal = terminal_attempts.get(attempt_id)
            if previous_terminal is not None:
                raise IdentityContractError(
                    f"deployment attempt {attempt_id!r} has multiple terminal receipts"
                )
            terminal_attempts[attempt_id] = receipt_type
            if receipt_type == "activation":
                activation_attempts[attempt_id] = receipt
        elif receipt_type == "recovery_protection":
            attempt_id = str(receipt["deployment_attempt_id"])
            if attempt_id in protection_attempts:
                raise IdentityContractError(
                    f"deployment attempt {attempt_id!r} has multiple protection receipts"
                )
            protection_attempts[attempt_id] = receipt

    for attempt_id, activation in activation_attempts.items():
        protection = protection_attempts.get(attempt_id)
        if protection is None:
            raise IdentityContractError(
                f"activation attempt {attempt_id!r} lacks prior recovery protection"
            )
        for field in (
            "release_manifest_sha256",
            "recovery_manifest_sha256",
            "checkpoint_manifest_sha256",
        ):
            if protection[field] != activation[field]:
                raise IdentityContractError(
                    f"activation attempt {attempt_id!r} changed protected R/RM/C closure"
                )
        if _parsed_timestamp(
            protection["recorded_at"], label="protection recorded_at"
        ) >= _parsed_timestamp(activation["recorded_at"], label="activation recorded_at"):
            raise IdentityContractError(
                f"activation attempt {attempt_id!r} predates recovery protection"
            )

    _assert_acyclic(edges)
    return IdentityGraphReport(
        active_manifest_sha256=active_hash,
        release_count=len(releases),
        checkpoint_count=len(checkpoints),
        recovery_manifest_count=len(recoveries),
        receipt_count=len(receipt_ids),
        edges=tuple(sorted(edges)),
    )


def lint_state_only_transition(
    *,
    release_before: object,
    release_after: object,
    active_before: object,
    active_after: object,
) -> None:
    """证明 state-only backup 没有让 immutable R 或 active identity 漂移。"""

    before_release = validate_release_manifest(release_before)
    after_release = validate_release_manifest(release_after)
    before_active = validate_active_release(active_before)
    after_active = validate_active_release(active_after)
    if manifest_sha256(before_release) != manifest_sha256(after_release):
        raise IdentityContractError("state-only operation modified release identity")
    if canonical_manifest_bytes(before_active) != canonical_manifest_bytes(after_active):
        raise IdentityContractError("state-only operation modified active authority")
