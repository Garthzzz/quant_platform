"""Immutable release, active-pointer and local deployment receipt contracts."""

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
LOCAL_ACTIVATION_SCHEMA = "qrh-local-activation-receipt/v1"
FAILURE_SCHEMA = "qrh-failure-receipt/v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_RECEIPT_AUTHORITY_KEYS = {
    "active_authority", "active_pointer", "active_release",
    "active_release_json", "active_manifest_sha256", "current",
    "current_release", "current_manifest_sha256", "is_active_authority",
    "release_path",
}


class IdentityContractError(ValueError):
    """An immutable identity or append-only receipt violates its contract."""


@dataclass(frozen=True)
class IdentityGraphReport:
    active_manifest_sha256: str
    release_count: int
    receipt_count: int
    edges: tuple[tuple[str, str], ...]


def canonical_manifest_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
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
        not isinstance(value, str) or not value or len(value) > max_length
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
        if key.casefold().endswith("_sha256"):
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
    release = _mapping(value, label="release_manifest")
    core_fields = {
        "schema_version", "release_id", "built_at", "application", "content",
        "resources", "state",
    }
    _required(release, core_fields, label="release_manifest")
    extra_fields = set(release) - core_fields - {"inventory"}
    if extra_fields:
        raise IdentityContractError(
            f"release_manifest contains forbidden fields: {sorted(extra_fields)}"
        )
    if release["schema_version"] != RELEASE_SCHEMA:
        raise IdentityContractError("release_manifest has unsupported schema_version")
    _identifier(release["release_id"], label="release_manifest.release_id")
    _timestamp(release["built_at"], label="release_manifest.built_at")

    application = _mapping(release["application"], label="release_manifest.application")
    _required(
        application, ("commit_sha", "tracked_tree_sha256", "build_tool_version"),
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
            raise IdentityContractError("legacy broadcast requires the zero commit sentinel")
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
    _text(application["build_tool_version"], label="release_manifest.application.build_tool_version")

    content = _mapping(release["content"], label="release_manifest.content")
    _required(
        content,
        ("snapshot_id", "source_inventory_sha256", "ir_sha256",
         "knowledge_sha256", "search_sha256", "knowledge_enrichment"),
        label="release_manifest.content",
    )
    _identifier(content["snapshot_id"], label="release_manifest.content.snapshot_id")
    _mapping(content["knowledge_enrichment"], label="release_manifest.content.knowledge_enrichment")
    resources = _mapping(release["resources"], label="release_manifest.resources")
    _required(resources, ("inventory_sha256",), label="release_manifest.resources")
    state = _mapping(release["state"], label="release_manifest.state")
    _required(state, ("compatibility",), label="release_manifest.state")
    _mapping(state["compatibility"], label="release_manifest.state.compatibility")
    if "inventory" in release:
        inventory = _mapping(release["inventory"], label="release_manifest.inventory")
        _required(inventory, ("schema_version", "files"), label="release_manifest.inventory")
    _validate_named_hashes(release, label="release_manifest")
    canonical_manifest_bytes(release)
    return release


def validate_active_release(value: object) -> Mapping[str, object]:
    active = _mapping(value, label="active_release")
    _exact_fields(
        active, ("schema_version", "release_id", "release_path", "manifest_sha256"),
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


def _receipt_common(receipt: Mapping[str, object]) -> str:
    schemas = {LOCAL_ACTIVATION_SCHEMA: "activation", FAILURE_SCHEMA: "failure"}
    schema = receipt.get("schema_version")
    receipt_type = schemas.get(schema) if isinstance(schema, str) else None
    if receipt_type is None:
        raise IdentityContractError("receipt has unsupported schema_version")
    if receipt.get("receipt_type") != receipt_type:
        raise IdentityContractError("receipt_type does not match schema_version")
    _identifier(receipt.get("receipt_id"), label="receipt.receipt_id")
    _timestamp(receipt.get("recorded_at"), label="receipt.recorded_at")
    if receipt.get("authority") != "evidence_only":
        raise IdentityContractError("receipt authority must be evidence_only")
    for path, key, _ in _walk(receipt):
        if key.casefold().replace("-", "_") in _RECEIPT_AUTHORITY_KEYS:
            raise IdentityContractError(
                f"receipt cannot define active authority at {'.'.join(path)}"
            )
    return receipt_type


def validate_receipt(value: object) -> Mapping[str, object]:
    receipt = _mapping(value, label="receipt")
    receipt_type = _receipt_common(receipt)
    common = {"schema_version", "receipt_type", "receipt_id", "recorded_at", "authority"}
    if receipt_type == "activation":
        _exact_fields(
            receipt,
            common | {"deployment_attempt_id", "release_manifest_sha256",
                      "prior_manifest_sha256", "verdict", "switch",
                      "post_activation_verification"},
            label="activation_receipt",
        )
        _identifier(receipt["deployment_attempt_id"], label="receipt.deployment_attempt_id")
        if receipt["verdict"] != "activated":
            raise IdentityContractError("activation verdict must be activated")
        _validate_bool_fields(
            receipt["switch"], ("active_pointer_switched", "candidate_started"),
            label="receipt.switch", expected=True,
        )
        _validate_bool_fields(
            receipt["post_activation_verification"],
            ("health", "critical_functions", "writer_fence"),
            label="receipt.post_activation_verification", expected=True,
        )
    else:
        _exact_fields(
            receipt,
            common | {"deployment_attempt_id", "candidate_manifest_sha256",
                      "prior_manifest_sha256", "verdict", "failed_phase",
                      "error_code", "rollback"},
            label="failure_receipt",
        )
        _identifier(receipt["deployment_attempt_id"], label="receipt.deployment_attempt_id")
        if receipt["verdict"] != "failed":
            raise IdentityContractError("failure receipt verdict must be failed")
        _text(receipt["failed_phase"], label="failure receipt failed_phase")
        _text(receipt["error_code"], label="failure receipt error_code")
        rollback = _mapping(receipt["rollback"], label="failure receipt rollback")
        _exact_fields(rollback, ("attempted", "succeeded"), label="failure receipt rollback")
        if not isinstance(rollback["attempted"], bool) or not isinstance(rollback["succeeded"], bool):
            raise IdentityContractError("failure receipt rollback flags must be boolean")
        if rollback["succeeded"] and not rollback["attempted"]:
            raise IdentityContractError("rollback cannot succeed unless attempted")
    _validate_named_hashes(receipt, label="receipt")
    canonical_manifest_bytes(receipt)
    return receipt


def authorize_receipt_append(
    value: object, *, observed_active_release: object | None = None,
    existing_receipts: Sequence[object] = (),
) -> Mapping[str, object]:
    receipt = validate_receipt(value)
    if receipt["receipt_type"] == "activation":
        if observed_active_release is None:
            raise IdentityContractError(
                "activation receipt append requires observed post-switch active authority"
            )
        active = validate_active_release(observed_active_release)
        if active["manifest_sha256"] != receipt["release_manifest_sha256"]:
            raise IdentityContractError(
                "activation receipt release does not match observed active authority"
            )
    attempt_id = str(receipt["deployment_attempt_id"])
    if any(
        existing.get("deployment_attempt_id") == attempt_id
        for existing in (validate_receipt(item) for item in existing_receipts)
    ):
        raise IdentityContractError(
            "deployment attempt already has a terminal activation/failure receipt"
        )
    return receipt


def lint_identity_graph(
    *, release_manifests: Sequence[object], active_release: object,
    receipts: Sequence[object] = (),
) -> IdentityGraphReport:
    releases: dict[str, Mapping[str, object]] = {}
    release_ids: dict[str, str] = {}
    for value in release_manifests:
        release = validate_release_manifest(value)
        digest = manifest_sha256(release)
        release_id = str(release["release_id"])
        if digest in releases or release_id in release_ids:
            raise IdentityContractError("release identity is duplicated")
        releases[digest] = release
        release_ids[release_id] = digest
    active = validate_active_release(active_release)
    active_hash = str(active["manifest_sha256"])
    if active_hash not in releases or release_ids.get(str(active["release_id"])) != active_hash:
        raise IdentityContractError("active release does not resolve to an exact release")
    edges: list[tuple[str, str]] = [("active", f"R:{active_hash}")]
    receipt_ids: set[str] = set()
    terminal_attempts: set[str] = set()
    for value in receipts:
        receipt = validate_receipt(value)
        receipt_id = str(receipt["receipt_id"])
        attempt_id = str(receipt["deployment_attempt_id"])
        if receipt_id in receipt_ids or attempt_id in terminal_attempts:
            raise IdentityContractError("deployment receipt identity is duplicated")
        receipt_ids.add(receipt_id)
        terminal_attempts.add(attempt_id)
        candidate_field = (
            "release_manifest_sha256"
            if receipt["receipt_type"] == "activation"
            else "candidate_manifest_sha256"
        )
        candidate_hash = str(receipt[candidate_field])
        prior_hash = str(receipt["prior_manifest_sha256"])
        if candidate_hash not in releases or prior_hash not in releases:
            raise IdentityContractError("receipt release edge is dangling")
        node = f"receipt:{manifest_sha256(receipt)}"
        edges.extend(((node, f"R:{candidate_hash}"), (node, f"R:{prior_hash}")))
    return IdentityGraphReport(
        active_manifest_sha256=active_hash,
        release_count=len(releases),
        receipt_count=len(receipt_ids),
        edges=tuple(sorted(edges)),
    )


__all__ = [
    "ACTIVE_SCHEMA", "FAILURE_SCHEMA", "LOCAL_ACTIVATION_SCHEMA", "RELEASE_SCHEMA",
    "IdentityContractError", "IdentityGraphReport", "authorize_receipt_append",
    "canonical_manifest_bytes", "lint_identity_graph", "manifest_sha256",
    "validate_active_release", "validate_receipt", "validate_release_manifest",
]
