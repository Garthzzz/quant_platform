"""本机 active/prior 发布对象的 v2 纯身份合同。

该模块只验证 canonical JSON、不可变 hash 与引用图，不读取文件系统、不执行
部署，也不把自报的 started/health/writer-fence 布尔值提升为资格能力。动态探针
与同锁切换必须由后续 DeploymentController 集成承担。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Iterable, Mapping, Sequence
import unicodedata


RELEASE_MANIFEST_SCHEMA = "qrh-release-manifest/v2"
ACTIVE_RELEASE_SCHEMA = "qrh-active-release/v2"
LOCAL_PRIOR_BINDING_SCHEMA = "qrh-local-prior-binding/v1"
LOCAL_STATE_IDENTITY_SCHEMA = "qrh-local-state-identity/v2"
ACTIVATION_RECEIPT_SCHEMA = "qrh-local-activation-receipt/v1"
ROLLBACK_RECEIPT_SCHEMA = "qrh-local-rollback-receipt/v1"
FAILURE_RECEIPT_SCHEMA = "qrh-local-failure-receipt/v1"
CLEANUP_RECEIPT_SCHEMA = "qrh-local-cleanup-receipt/v1"

PRODUCTION_VM_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
PRODUCTION_RELEASE_ROOT = PRODUCTION_VM_ROOT / "releases"
PRODUCTION_STATE_ROOT = PRODUCTION_VM_ROOT / "state"
PRODUCTION_CONTROL_ROOT = PRODUCTION_VM_ROOT / "control"
PRODUCTION_INCOMING_ROOT = PRODUCTION_VM_ROOT / "incoming"
PRODUCTION_OBJECT_ROOT = PRODUCTION_VM_ROOT / "objects"
PRODUCTION_RECEIPT_ROOT = PRODUCTION_VM_ROOT / "audit" / "receipts"

_PRODUCTION_STATE_SCHEMA_VERSIONS = {
    "comments": 2,
    "research_workspace": 3,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ACRONYM_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_CASE_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_MAX_INVENTORY_FILES = 200_000
_MAX_INVENTORY_BYTES = 32 * 1024 * 1024 * 1024
_MAX_REMOVED_TARGETS = 10_000
_MAX_CONTROL_IDENTITY_WINDOW_SEGMENTS = 8
_MAX_CONTROL_IDENTITY_WINDOW_CHARACTERS = 4_096

_RELEASE_TOP_LEVEL_FIELDS = {
    "schema_version",
    "release_id",
    "built_at",
    "application",
    "content",
    "resources",
    "state",
    "inventory",
}
_WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class LocalReleaseIdentityError(ValueError):
    """v2 本机发布身份或引用图不满足 closed contract。"""


@dataclass(frozen=True, slots=True)
class LocalReleaseGraphReport:
    active_manifest_sha256: str
    prior_manifest_sha256: str
    release_manifest_count: int
    retained_release_count: int
    receipt_count: int
    edges: tuple[tuple[str, str], ...]


def _normalized_object_key(key: str) -> str:
    normalized = unicodedata.normalize("NFKC", key)
    expanded = _ACRONYM_BOUNDARY_RE.sub("_", normalized)
    expanded = _CAMEL_CASE_BOUNDARY_RE.sub("_", expanded)
    tokens: list[str] = []
    current: list[str] = []
    for character in expanded:
        if character.isalnum():
            current.append(character.casefold())
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    if not tokens:
        raise LocalReleaseIdentityError("object key normalization is empty")
    return "_".join(tokens)


def _validate_json_value(value: object) -> None:
    """Reject Python values that JSON would coerce or encode non-portably."""

    value_type = type(value)
    if value is None or value_type in {bool, int, str}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise LocalReleaseIdentityError("value is not canonical JSON")
        return
    if value_type is list:
        for child in value:
            _validate_json_value(child)
        return
    if value_type is dict:
        normalized_keys: dict[str, str] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise LocalReleaseIdentityError("value is not canonical JSON")
            normalized = _normalized_object_key(key)
            previous = normalized_keys.get(normalized)
            if previous is not None and previous != key:
                raise LocalReleaseIdentityError(
                    "object key normalization collision"
                )
            normalized_keys[normalized] = key
            _validate_json_value(child)
        return
    raise LocalReleaseIdentityError("value is not canonical JSON")


def canonical_bytes(value: object) -> bytes:
    try:
        _validate_json_value(value)
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return rendered.encode("utf-8")
    except LocalReleaseIdentityError:
        raise
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise LocalReleaseIdentityError("value is not canonical JSON") from error


def identity_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _clone(value: object, *, label: str) -> Mapping[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalReleaseIdentityError(f"{label} is not canonical JSON") from error
    if not isinstance(cloned, dict):
        raise LocalReleaseIdentityError(f"{label} must be a JSON object")
    return cloned


def _object(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LocalReleaseIdentityError(f"{label} must be a JSON object")
    return value


def _closed(
    value: object, fields: Iterable[str], *, label: str
) -> Mapping[str, object]:
    document = _object(value, label=label)
    if set(document) != set(fields):
        raise LocalReleaseIdentityError(f"{label} schema is not closed")
    return document


def _text(value: object, *, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _CONTROL_RE.search(value)
    ):
        raise LocalReleaseIdentityError(f"{label} must be non-empty control-free text")
    return value


def _identifier(value: object, *, label: str) -> str:
    rendered = _text(value, label=label, maximum=180)
    win32_stem = unicodedata.normalize("NFKC", rendered).split(".", 1)[0].casefold()
    if (
        _ID_RE.fullmatch(rendered) is None
        or ".." in rendered
        or rendered.endswith((".", " "))
        or win32_stem in _WINDOWS_DEVICE_NAMES
    ):
        raise LocalReleaseIdentityError(f"{label} is not a stable identifier")
    return rendered


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise LocalReleaseIdentityError(f"{label} must be lowercase SHA-256")
    if set(value) == {"0"}:
        raise LocalReleaseIdentityError(f"{label} cannot use a zero SHA-256")
    return value


def _timestamp(value: object, *, label: str) -> datetime:
    rendered = _text(value, label=label, maximum=64)
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError as error:
        raise LocalReleaseIdentityError(f"{label} must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LocalReleaseIdentityError(f"{label} must include a timezone")
    return parsed


def _nonnegative_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LocalReleaseIdentityError(f"{label} must be a non-negative integer")
    return value


def _verify_self_hash(
    document: Mapping[str, object], *, field: str, label: str
) -> str:
    expected = _sha256(document.get(field), label=f"{label}.{field}")
    material = dict(document)
    material.pop(field, None)
    if identity_sha256(material) != expected:
        raise LocalReleaseIdentityError(f"{label} self hash differs")
    return expected


def _walk_scalars(
    value: object, path: tuple[str, ...] = ()
):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_scalars(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_scalars(child, (*path, str(index)))
    else:
        yield path, value


def _walk_string_sequences(
    value: object, path: tuple[str, ...] = ()
):  # type: ignore[no-untyped-def]
    """Yield adjacent direct string runs without flattening unrelated branches."""

    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_string_sequences(child, (*path, key))
    elif isinstance(value, list):
        run: list[str] = []
        run_start = 0
        for index, child in enumerate(value):
            if isinstance(child, str):
                if not run:
                    run_start = index
                run.append(child)
                continue
            if len(run) >= 2:
                yield (*path, str(run_start)), tuple(run)
            run = []
            yield from _walk_string_sequences(child, (*path, str(index)))
        if len(run) >= 2:
            yield (*path, str(run_start)), tuple(run)


def _normalized_control_identity(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _validate_provenance(value: object) -> Mapping[str, object]:
    provenance = _closed(
        value,
        {"builder", "labels"},
        label="release application provenance",
    )
    _identifier(provenance["builder"], label="application provenance builder")
    labels = provenance["labels"]
    if not isinstance(labels, list):
        raise LocalReleaseIdentityError("application provenance labels must be a list")
    rendered = [
        _text(label, label="application provenance label", maximum=180)
        for label in labels
    ]
    if rendered != sorted(set(rendered)):
        raise LocalReleaseIdentityError(
            "application provenance labels must be sorted and unique"
        )
    return provenance


def _validate_application(value: object) -> Mapping[str, object]:
    application = _object(value, label="release application")
    source_kind = application.get("source_kind")
    if source_kind == "git":
        application = _closed(
            application,
            {
                "source_kind",
                "commit_sha",
                "tracked_tree_sha256",
                "build_tool_version",
                "provenance",
            },
            label="release application",
        )
        commit = application["commit_sha"]
        if not isinstance(commit, str) or _COMMIT_RE.fullmatch(commit) is None:
            raise LocalReleaseIdentityError("application commit_sha is invalid")
        if set(commit) == {"0"}:
            raise LocalReleaseIdentityError("Git release cannot use a zero commit")
        _sha256(
            application["tracked_tree_sha256"],
            label="application tracked tree",
        )
    elif source_kind == "legacy_broadcast":
        application = _closed(
            application,
            {
                "source_kind",
                "source_archive_sha256",
                "legacy_deployment_id",
                "build_tool_version",
                "provenance",
            },
            label="release application",
        )
        _sha256(
            application["source_archive_sha256"],
            label="legacy source archive",
        )
        _identifier(
            application["legacy_deployment_id"],
            label="legacy deployment ID",
        )
    else:
        raise LocalReleaseIdentityError("application source_kind is invalid")
    _text(application["build_tool_version"], label="application build tool")
    _validate_provenance(application["provenance"])
    return application


def _validate_knowledge_enrichment(value: object) -> Mapping[str, object]:
    enrichment = _object(value, label="content knowledge_enrichment")
    status = enrichment.get("status")
    if status == "not_applicable":
        return _closed(
            enrichment,
            {"status"},
            label="content knowledge_enrichment",
        )
    if status == "pending":
        enrichment = _closed(
            enrichment,
            {"status", "job_identity_sha256"},
            label="content knowledge_enrichment",
        )
        _sha256(enrichment["job_identity_sha256"], label="pending job identity")
        return enrichment
    if status == "failed_retryable":
        enrichment = _closed(
            enrichment,
            {"status", "failure_identity_sha256"},
            label="content knowledge_enrichment",
        )
        _sha256(
            enrichment["failure_identity_sha256"],
            label="knowledge failure identity",
        )
        return enrichment
    if status == "blocked_policy":
        enrichment = _closed(
            enrichment,
            {"status", "policy_identity_sha256"},
            label="content knowledge_enrichment",
        )
        _sha256(
            enrichment["policy_identity_sha256"],
            label="knowledge policy identity",
        )
        return enrichment
    if status == "ready":
        enrichment = _closed(
            enrichment,
            {
                "status",
                "generation_id",
                "provider_revision",
                "model_identity_sha256",
                "accepted_knowledge_sha256",
                "coverage_report_sha256",
            },
            label="content knowledge_enrichment",
        )
        _identifier(enrichment["generation_id"], label="knowledge generation ID")
        _text(
            enrichment["provider_revision"],
            label="knowledge provider revision",
            maximum=180,
        )
        for field in (
            "model_identity_sha256",
            "accepted_knowledge_sha256",
            "coverage_report_sha256",
        ):
            _sha256(enrichment[field], label=f"knowledge {field}")
        return enrichment
    if status == "ready_set":
        enrichment = _closed(
            enrichment,
            {
                "status",
                "generation_membership_sha256",
                "status_membership_sha256",
                "semantic_authority_sha256",
            },
            label="content knowledge_enrichment",
        )
        for field in (
            "generation_membership_sha256",
            "status_membership_sha256",
            "semantic_authority_sha256",
        ):
            _sha256(enrichment[field], label=f"knowledge {field}")
        return enrichment
    raise LocalReleaseIdentityError("content knowledge_enrichment status is invalid")


def _validate_content(value: object) -> Mapping[str, object]:
    content = _closed(
        value,
        {
            "snapshot_id",
            "source_inventory_sha256",
            "ir_sha256",
            "knowledge_sha256",
            "search_sha256",
            "page_projection_sha256",
            "mcp_sha256",
            "active_membership_sha256",
            "knowledge_enrichment",
            "presentation",
        },
        label="release content",
    )
    _identifier(content["snapshot_id"], label="content snapshot_id")
    for field in (
        "source_inventory_sha256",
        "ir_sha256",
        "knowledge_sha256",
        "search_sha256",
        "page_projection_sha256",
        "mcp_sha256",
        "active_membership_sha256",
    ):
        _sha256(content[field], label=f"content {field}")
    _validate_knowledge_enrichment(content["knowledge_enrichment"])
    presentation = _closed(
        content["presentation"],
        {"language"},
        label="content presentation",
    )
    _text(presentation["language"], label="content presentation language", maximum=32)
    return content


def _validate_compatibility(value: object) -> Mapping[str, object]:
    compatibility = _object(value, label="release state compatibility")
    if (
        set(compatibility)
        != {*_PRODUCTION_STATE_SCHEMA_VERSIONS, "rollback_policy"}
        or compatibility.get("rollback_policy")
        != "expand_only_no_down_migration"
    ):
        raise LocalReleaseIdentityError(
            "state compatibility must use the exact production database set "
            "and expand-only/no-down-migration"
        )
    for database, raw_contract in compatibility.items():
        if database == "rollback_policy":
            continue
        _identifier(database, label="state database identity")
        contract = _closed(
            raw_contract,
            {"read", "write"},
            label="state database compatibility",
        )
        for lane_name in ("read", "write"):
            lane = contract[lane_name]
            if (
                not isinstance(lane, list)
                or not lane
                or any(
                    isinstance(version, bool)
                    or not isinstance(version, int)
                    or version < 1
                    for version in lane
                )
                or lane != sorted(set(lane))
            ):
                raise LocalReleaseIdentityError(
                    "state read/write versions must be sorted unique positive integers"
                )
    return compatibility


def _validate_inventory(value: object) -> Mapping[str, object]:
    inventory = _closed(
        value,
        {"schema_version", "files"},
        label="release inventory",
    )
    if inventory["schema_version"] != "qrh-release-file-inventory/v2":
        raise LocalReleaseIdentityError("release inventory schema version differs")
    files = inventory["files"]
    if (
        not isinstance(files, list)
        or not files
        or len(files) > _MAX_INVENTORY_FILES
    ):
        if isinstance(files, list) and not files:
            raise LocalReleaseIdentityError("release inventory cannot be empty")
        raise LocalReleaseIdentityError("release inventory file list is invalid")
    paths: list[str] = []
    folded_components: dict[str, tuple[str, str]] = {}
    total_bytes = 0
    forbidden_windows = set('<>:"|?*')
    for raw in files:
        record = _closed(
            raw,
            {"path", "bytes", "sha256"},
            label="release inventory record",
        )
        relative = record["path"]
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise LocalReleaseIdentityError("release inventory path is invalid")
        parsed = PurePosixPath(relative)
        normalized_relative = unicodedata.normalize("NFKC", relative)
        if (
            relative == "."
            or parsed.is_absolute()
            or ".." in parsed.parts
            or parsed.as_posix() != relative
            or normalized_relative.casefold() == "release_manifest.json"
            or any(
                unicodedata.normalize("NFKC", part).casefold()
                == "release_manifest.json"
                for part in parsed.parts
            )
        ):
            raise LocalReleaseIdentityError("release inventory path is unsafe on Windows")
        prefix: list[str] = []
        for index, part in enumerate(parsed.parts):
            prefix.append(part)
            normalized_part = unicodedata.normalize("NFKC", part)
            if (
                not part
                or part.endswith((".", " "))
                or normalized_part.endswith((".", " "))
                # Win32 forbids the ASCII characters in the physical name,
                # not unrelated Unicode punctuation that NFKC renders as an
                # ASCII lookalike.  Keep NFKC for collision and device-name
                # protection below, while checking the actual path component
                # for the physical Win32 character restriction.  This is
                # required for byte-exact Chinese research names containing
                # legitimate fullwidth punctuation such as ``：`` and ``？``.
                or any(character in forbidden_windows for character in part)
                or any(ord(character) < 32 or ord(character) == 127 for character in part)
                or normalized_part.split(".", 1)[0].casefold()
                in _WINDOWS_DEVICE_NAMES
            ):
                raise LocalReleaseIdentityError("release inventory path is unsafe on Windows")
            logical = "/".join(prefix)
            folded = unicodedata.normalize("NFKC", logical).casefold()
            role = "file" if index == len(parsed.parts) - 1 else "directory"
            previous = folded_components.get(folded)
            if previous is not None:
                previous_logical, previous_role = previous
                if previous_logical != logical:
                    raise LocalReleaseIdentityError(
                        "release inventory has a case-fold collision"
                    )
                if previous_role != role:
                    raise LocalReleaseIdentityError(
                        "release inventory has a file-directory prefix collision"
                    )
            else:
                folded_components[folded] = (logical, role)
        size = _nonnegative_int(record["bytes"], label="release inventory bytes")
        total_bytes += size
        if total_bytes > _MAX_INVENTORY_BYTES:
            raise LocalReleaseIdentityError("release inventory exceeds byte bound")
        _sha256(record["sha256"], label="release inventory file hash")
        paths.append(relative)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise LocalReleaseIdentityError("release inventory paths must be sorted and unique")
    return inventory


def validate_release_manifest(value: object) -> Mapping[str, object]:
    """Validate immutable R v2 with no recovery/control back-reference surface."""

    canonical_bytes(value)
    release = _closed(value, _RELEASE_TOP_LEVEL_FIELDS, label="release manifest")
    if release["schema_version"] != RELEASE_MANIFEST_SCHEMA:
        raise LocalReleaseIdentityError("release manifest schema version differs")
    _identifier(release["release_id"], label="release_id")
    _timestamp(release["built_at"], label="release built_at")
    _validate_application(release["application"])
    _validate_content(release["content"])
    resources = _closed(
        release["resources"],
        {"inventory_sha256"},
        label="release resources",
    )
    state = _closed(
        release["state"],
        {"compatibility"},
        label="release state",
    )
    _validate_compatibility(state["compatibility"])
    inventory = _validate_inventory(release["inventory"])
    if resources["inventory_sha256"] != identity_sha256(inventory):
        raise LocalReleaseIdentityError("resources do not bind the exact inventory")
    return _clone(release, label="release manifest")


def _release_ref(value: object, *, label: str) -> Mapping[str, object]:
    reference = _closed(
        value,
        {"release_id", "release_path", "manifest_sha256"},
        label=label,
    )
    release_id = _identifier(reference["release_id"], label=f"{label}.release_id")
    expected_path = str(PRODUCTION_RELEASE_ROOT / release_id)
    if reference["release_path"] != expected_path:
        raise LocalReleaseIdentityError(f"{label} path is not its exact D release path")
    _sha256(reference["manifest_sha256"], label=f"{label}.manifest_sha256")
    return reference


def validate_active_release(value: object) -> Mapping[str, object]:
    """Validate the only current pointer; no binding/receipt fields are accepted."""

    active = _closed(
        value,
        {"schema_version", "release"},
        label="active release",
    )
    if active["schema_version"] != ACTIVE_RELEASE_SCHEMA:
        raise LocalReleaseIdentityError("active release schema version differs")
    _release_ref(active["release"], label="active release ref")
    return _clone(active, label="active release")


def _schema_versions(value: object, *, label: str) -> Mapping[str, int]:
    versions = _object(value, label=label)
    if not versions:
        raise LocalReleaseIdentityError(f"{label} cannot be empty")
    result: dict[str, int] = {}
    for database, version in versions.items():
        _identifier(database, label=f"{label} database")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise LocalReleaseIdentityError(f"{label} versions must be positive integers")
        result[database] = version
    return result


def validate_state_identity(value: object) -> Mapping[str, object]:
    state = _closed(
        value,
        {
            "schema_version",
            "authority_id",
            "state_path",
            "schema_versions",
            "identity_sha256",
        },
        label="local state identity",
    )
    if state["schema_version"] != LOCAL_STATE_IDENTITY_SCHEMA:
        raise LocalReleaseIdentityError("local state identity schema version differs")
    _identifier(state["authority_id"], label="state authority_id")
    if state["state_path"] != str(PRODUCTION_STATE_ROOT):
        raise LocalReleaseIdentityError("state identity does not bind the exact D state root")
    schema_versions = _schema_versions(
        state["schema_versions"], label="state schema_versions"
    )
    if schema_versions != _PRODUCTION_STATE_SCHEMA_VERSIONS:
        raise LocalReleaseIdentityError(
            "state identity does not bind the exact production schema versions"
        )
    _verify_self_hash(state, field="identity_sha256", label="state identity")
    return _clone(state, label="state identity")


def _pair(value: object, *, label: str, allow_missing_prior: bool) -> Mapping[str, object]:
    pair = _closed(value, {"active", "prior"}, label=label)
    active = _release_ref(pair["active"], label=f"{label}.active")
    prior_value = pair["prior"]
    if prior_value is None:
        if not allow_missing_prior:
            raise LocalReleaseIdentityError(f"{label} requires exactly one prior")
        return pair
    prior = _release_ref(prior_value, label=f"{label}.prior")
    if (
        active["release_id"].casefold() == prior["release_id"].casefold()
        or active["manifest_sha256"] == prior["manifest_sha256"]
    ):
        raise LocalReleaseIdentityError(f"{label} active and prior must be distinct")
    return pair


def _pair_hash(pair: Mapping[str, object]) -> str:
    return identity_sha256(pair)


def validate_local_prior_binding(value: object) -> Mapping[str, object]:
    """Validate one evidence binding; it never defines current authority."""

    binding = _closed(
        value,
        {
            "schema_version",
            "binding_id",
            "recorded_at",
            "authority",
            "active",
            "prior",
            "state_identity",
            "result",
            "binding_sha256",
        },
        label="local prior binding",
    )
    if (
        binding["schema_version"] != LOCAL_PRIOR_BINDING_SCHEMA
        or binding["authority"] != "retention_evidence_only"
    ):
        raise LocalReleaseIdentityError("local prior binding identity differs")
    _identifier(binding["binding_id"], label="binding_id")
    _timestamp(binding["recorded_at"], label="binding recorded_at")
    pair = _pair(
        {"active": binding["active"], "prior": binding["prior"]},
        label="binding pair",
        allow_missing_prior=False,
    )
    validate_state_identity(binding["state_identity"])
    result = _closed(
        binding["result"],
        {"status", "pair_sha256", "retained_release_count", "state_policy"},
        label="binding result",
    )
    if (
        result["status"] != "bound"
        or result["pair_sha256"] != _pair_hash(pair)
        or result["retained_release_count"] != 2
        or result["state_policy"] != "expand_only_no_down_migration"
    ):
        raise LocalReleaseIdentityError("binding result does not close the active/prior pair")
    _verify_self_hash(binding, field="binding_sha256", label="local prior binding")
    return _clone(binding, label="local prior binding")


def _receipt_common(
    value: object,
    *,
    schema: str,
    fields: set[str],
    label: str,
) -> Mapping[str, object]:
    receipt = _closed(
        value,
        {
            "schema_version",
            "receipt_id",
            "attempt_id",
            "recorded_at",
            "authority",
            *fields,
            "receipt_sha256",
        },
        label=label,
    )
    if receipt["schema_version"] != schema or receipt["authority"] != "evidence_only":
        raise LocalReleaseIdentityError(f"{label} identity differs")
    _identifier(receipt["receipt_id"], label=f"{label}.receipt_id")
    _identifier(receipt["attempt_id"], label=f"{label}.attempt_id")
    _timestamp(receipt["recorded_at"], label=f"{label}.recorded_at")
    return receipt


def _transition_receipt(
    value: object,
    *,
    schema: str,
    status: str,
    operation: str,
    label: str,
) -> Mapping[str, object]:
    document = _object(value, label=label)
    observed_operation = document.get("operation")
    if schema == ACTIVATION_RECEIPT_SCHEMA and observed_operation == "bootstrap_first_pair":
        receipt = _receipt_common(
            document,
            schema=schema,
            fields={
                "operation",
                "original",
                "pair",
                "state_identity",
                "proof",
                "result",
            },
            label=label,
        )
        original = _closed(
            receipt["original"],
            {"active_pointer_status", "local_prior_binding_status"},
            label="bootstrap original authority",
        )
        if original != {
            "active_pointer_status": "absent",
            "local_prior_binding_status": "absent",
        }:
            raise LocalReleaseIdentityError(
                "bootstrap requires original pointer and binding absent"
            )
        pair = _pair(
            receipt["pair"],
            label="bootstrap result pair",
            allow_missing_prior=True,
        )
        if pair["prior"] is not None:
            raise LocalReleaseIdentityError("bootstrap result prior must be null")
        state_identity = validate_state_identity(receipt["state_identity"])
        proof = _closed(
            receipt["proof"],
            {
                "ingress_status",
                "legacy_c_writer_status",
                "r0_live",
                "writer_fence_sha256",
            },
            label="bootstrap proof",
        )
        if (
            proof["ingress_status"] != "closed"
            or proof["legacy_c_writer_status"] != "fenced"
            or _release_ref(proof["r0_live"], label="bootstrap R0 live ref")
            != pair["active"]
        ):
            raise LocalReleaseIdentityError("bootstrap proof identity differs")
        _sha256(proof["writer_fence_sha256"], label="bootstrap writer fence")
        result = _closed(
            receipt["result"],
            {
                "status",
                "pair_sha256",
                "state_identity_sha256",
                "proof_sha256",
            },
            label="bootstrap result",
        )
        if (
            result["status"] != "bootstrapped"
            or result["pair_sha256"] != _pair_hash(pair)
            or result["state_identity_sha256"]
            != state_identity["identity_sha256"]
            or result["proof_sha256"] != identity_sha256(proof)
        ):
            raise LocalReleaseIdentityError("bootstrap result evidence differs")
        _verify_self_hash(receipt, field="receipt_sha256", label=label)
        return _clone(receipt, label=label)

    receipt = _receipt_common(
        document,
        schema=schema,
        fields={"operation", "pair", "result"},
        label=label,
    )
    if observed_operation != operation:
        raise LocalReleaseIdentityError(f"{label} operation differs")
    pair = _pair(receipt["pair"], label=f"{label} pair", allow_missing_prior=False)
    result = _closed(
        receipt["result"],
        {"status", "pair_sha256", "controller_verification_sha256"},
        label=f"{label} result",
    )
    _sha256(
        result["controller_verification_sha256"],
        label=f"{label} controller verification",
    )
    if result["status"] != status or result["pair_sha256"] != _pair_hash(pair):
        raise LocalReleaseIdentityError(f"{label} result does not bind its pair")
    _verify_self_hash(receipt, field="receipt_sha256", label=label)
    return _clone(receipt, label=label)


def validate_activation_receipt(value: object) -> Mapping[str, object]:
    return _transition_receipt(
        value,
        schema=ACTIVATION_RECEIPT_SCHEMA,
        status="activated",
        operation="activate_successor",
        label="activation receipt",
    )


def validate_rollback_receipt(value: object) -> Mapping[str, object]:
    return _transition_receipt(
        value,
        schema=ROLLBACK_RECEIPT_SCHEMA,
        status="rolled_back",
        operation="rollback_to_prior",
        label="rollback receipt",
    )


def _failure_restoration_observation(
    value: object,
    *,
    detail_fields: set[str],
    label: str,
) -> Mapping[str, object]:
    observation = _closed(
        value,
        {
            "status",
            "evidence_sha256",
            "observation_sha256",
            *detail_fields,
        },
        label=label,
    )
    _sha256(observation["evidence_sha256"], label=f"{label} evidence")
    _verify_self_hash(observation, field="observation_sha256", label=label)
    return observation


def validate_failure_receipt(value: object) -> Mapping[str, object]:
    receipt = _receipt_common(
        value,
        schema=FAILURE_RECEIPT_SCHEMA,
        fields={
            "operation",
            "original_pair",
            "original_state_identity",
            "candidate",
            "failed_phase",
            "restoration_evidence",
            "result",
        },
        label="failure receipt",
    )
    operation = receipt["operation"]
    if operation not in {
        "activate_successor",
        "rollback_to_prior",
        "bootstrap_first_pair",
    }:
        raise LocalReleaseIdentityError("failure receipt operation is invalid")
    original = _closed(
        receipt["original_pair"],
        {"kind", "pair"},
        label="failure original pair",
    )
    original_kind = original["kind"]
    if original_kind == "bootstrap_no_d_pair":
        if original["pair"] is not None:
            raise LocalReleaseIdentityError(
                "bootstrap failure original pair must be null"
            )
        original_pair = None
    elif original_kind == "release_pair":
        original_pair = _pair(
            original["pair"],
            label="failure original release pair",
            allow_missing_prior=True,
        )
    else:
        raise LocalReleaseIdentityError("failure original pair kind is invalid")
    original_state_identity = validate_state_identity(
        receipt["original_state_identity"]
    )
    candidate = _release_ref(receipt["candidate"], label="failure candidate")
    original_refs: list[Mapping[str, object]] = []
    if original_pair is not None:
        original_refs.append(original_pair["active"])
        if original_pair["prior"] is not None:
            original_refs.append(original_pair["prior"])
    if operation == "bootstrap_first_pair":
        if original_kind != "bootstrap_no_d_pair":
            raise LocalReleaseIdentityError(
                "bootstrap failure requires bootstrap_no_d_pair"
            )
    elif operation == "activate_successor":
        if original_kind != "release_pair":
            raise LocalReleaseIdentityError(
                "activate_successor failure requires an original release pair"
            )
        if any(
            candidate["release_id"].casefold()
            == reference["release_id"].casefold()
            or candidate["manifest_sha256"] == reference["manifest_sha256"]
            for reference in original_refs
        ):
            raise LocalReleaseIdentityError(
                "activate_successor failure candidate must differ from original pair"
            )
    else:
        if (
            original_kind != "release_pair"
            or original_pair is None
            or original_pair["prior"] is None
            or candidate != original_pair["prior"]
        ):
            raise LocalReleaseIdentityError(
                "rollback_to_prior failure candidate must be the exact original prior"
            )
    _identifier(receipt["failed_phase"], label="failure failed_phase")

    evidence = _closed(
        receipt["restoration_evidence"],
        {
            "original_active_pointer_observation",
            "original_local_prior_binding_observation",
            "original_active_service_live_identity_observation",
            "original_active_writer_fence_observation",
            "current_d_state_identity_observation",
        },
        label="failure restoration evidence",
    )
    original_active = None if original_pair is None else original_pair["active"]
    original_binding_pair = (
        original_pair
        if original_pair is not None and original_pair["prior"] is not None
        else None
    )

    pointer = _failure_restoration_observation(
        evidence["original_active_pointer_observation"],
        detail_fields={"observed_release"},
        label="failure original active pointer observation",
    )
    expected_pointer_status = (
        "absent" if original_active is None else "original_active_restored"
    )
    if (
        pointer["status"] != expected_pointer_status
        or pointer["observed_release"] != original_active
    ):
        raise LocalReleaseIdentityError(
            "failure original active pointer observation differs"
        )
    if pointer["observed_release"] is not None:
        _release_ref(
            pointer["observed_release"],
            label="failure pointer observed release",
        )

    binding = _failure_restoration_observation(
        evidence["original_local_prior_binding_observation"],
        detail_fields={"observed_pair"},
        label="failure original local prior binding observation",
    )
    expected_binding_status = (
        "absent" if original_binding_pair is None else "original_binding_restored"
    )
    if (
        binding["status"] != expected_binding_status
        or binding["observed_pair"] != original_binding_pair
    ):
        raise LocalReleaseIdentityError(
            "failure original local prior binding observation differs"
        )
    if binding["observed_pair"] is not None:
        _pair(
            binding["observed_pair"],
            label="failure binding observed pair",
            allow_missing_prior=False,
        )

    service = _failure_restoration_observation(
        evidence["original_active_service_live_identity_observation"],
        detail_fields={"observed_release"},
        label="failure original active service live identity observation",
    )
    pre_ingress_baseline = (
        operation == "activate_successor"
        and original_pair is not None
        and original_pair["prior"] is None
        and service["status"] == "bootstrap_r0_ingress_closed"
    )
    expected_service_status = (
        "absent"
        if original_active is None
        else (
            "bootstrap_r0_ingress_closed"
            if pre_ingress_baseline
            else "original_active_live"
        )
    )
    if (
        service["status"] != expected_service_status
        or service["observed_release"] != original_active
    ):
        raise LocalReleaseIdentityError(
            "failure original active service live identity observation differs"
        )
    if service["observed_release"] is not None:
        _release_ref(
            service["observed_release"],
            label="failure service observed release",
        )

    writer = _failure_restoration_observation(
        evidence["original_active_writer_fence_observation"],
        detail_fields={"observed_release"},
        label="failure original active writer fence observation",
    )
    expected_writer_status = (
        "d_writer_absent_or_fenced"
        if original_active is None
        else (
            "bootstrap_r0_writer_fenced"
            if pre_ingress_baseline
            else "original_active_writer_fence_restored"
        )
    )
    if (
        writer["status"] != expected_writer_status
        or writer["observed_release"] != original_active
    ):
        raise LocalReleaseIdentityError(
            "failure original active writer fence observation differs"
        )
    if writer["observed_release"] is not None:
        _release_ref(
            writer["observed_release"],
            label="failure writer observed release",
        )

    state = _failure_restoration_observation(
        evidence["current_d_state_identity_observation"],
        detail_fields={"observed_state_identity"},
        label="failure current D state identity observation",
    )
    expected_state_status = (
        "d_state_not_externally_written"
        if original_active is None
        else "current_d_state_identity_unchanged"
    )
    observed_state_identity = validate_state_identity(
        state["observed_state_identity"]
    )
    if (
        state["status"] != expected_state_status
        or observed_state_identity != original_state_identity
    ):
        raise LocalReleaseIdentityError(
            "failure current D state identity observation differs"
        )

    result = _closed(
        receipt["result"],
        {
            "status",
            "original_pair_sha256",
            "original_state_identity_sha256",
            "candidate_manifest_sha256",
            "restoration_evidence_sha256",
        },
        label="failure result",
    )
    if (
        result["status"] != "failed"
        or result["original_pair_sha256"] != identity_sha256(original)
        or result["original_state_identity_sha256"]
        != original_state_identity["identity_sha256"]
        or result["candidate_manifest_sha256"] != candidate["manifest_sha256"]
        or result["restoration_evidence_sha256"] != identity_sha256(evidence)
    ):
        raise LocalReleaseIdentityError(
            "failure result does not bind pair/candidate/original state/restoration evidence"
        )
    _verify_self_hash(receipt, field="receipt_sha256", label="failure receipt")
    return _clone(receipt, label="failure receipt")


def _exact_d_child_path(
    value: object,
    *,
    root: PureWindowsPath,
    label: str,
) -> str:
    rendered = _text(value, label=label, maximum=1024)
    parsed = PureWindowsPath(rendered)
    if str(parsed) != rendered:
        raise LocalReleaseIdentityError(f"{label} is not an exact D-root path")
    try:
        relative = parsed.relative_to(root)
    except ValueError as error:
        raise LocalReleaseIdentityError(f"{label} is not an exact D-root path") from error
    if str(root / relative) != rendered:
        raise LocalReleaseIdentityError(f"{label} is not an exact D-root path")
    if not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise LocalReleaseIdentityError(f"{label} is not an exact D-root path")
    forbidden_windows = set('<>:"|?*')
    for part in relative.parts:
        normalized = unicodedata.normalize("NFKC", part)
        if (
            normalized != part
            or part.endswith((".", " "))
            or normalized.endswith((".", " "))
            or any(character in forbidden_windows for character in normalized)
            or normalized.split(".", 1)[0].casefold() in _WINDOWS_DEVICE_NAMES
        ):
            raise LocalReleaseIdentityError(f"{label} is not an exact D-root path")
    return rendered


def _cleanup_target(value: object) -> Mapping[str, object]:
    target = _object(value, label="cleanup removed target")
    kind = target.get("kind")
    if kind == "release_closure":
        target = _closed(
            target,
            {"kind", "release", "closure_sha256"},
            label="cleanup release closure target",
        )
        _release_ref(target["release"], label="cleanup release closure ref")
        _sha256(
            target["closure_sha256"],
            label="cleanup release closure hash",
        )
        return target
    if kind in {"incoming", "partial"}:
        target = _closed(
            target,
            {"kind", "path", "payload_sha256", "closure_sha256"},
            label=f"cleanup {kind} target",
        )
        path = _exact_d_child_path(
            target["path"],
            root=PRODUCTION_INCOMING_ROOT,
            label=f"cleanup {kind} path",
        )
        is_partial = PureWindowsPath(path).name.casefold().endswith(".partial")
        if (kind == "partial") != is_partial:
            raise LocalReleaseIdentityError(
                "cleanup incoming/partial kind does not match exact path"
            )
        _sha256(target["payload_sha256"], label=f"cleanup {kind} payload hash")
        _sha256(target["closure_sha256"], label=f"cleanup {kind} closure hash")
        return target
    if kind == "unreferenced_object":
        target = _closed(
            target,
            {"kind", "path", "object_sha256", "closure_sha256"},
            label="cleanup unreferenced object target",
        )
        _exact_d_child_path(
            target["path"],
            root=PRODUCTION_OBJECT_ROOT,
            label="cleanup unreferenced object path",
        )
        _sha256(target["object_sha256"], label="cleanup object hash")
        _sha256(target["closure_sha256"], label="cleanup object closure hash")
        return target
    raise LocalReleaseIdentityError("cleanup removed target kind is invalid")


def _cleanup_target_sort_key(target: Mapping[str, object]) -> tuple[str, str, str]:
    kind, physical_path = _cleanup_target_physical_key(target)
    return kind, physical_path, identity_sha256(target)


def _cleanup_target_physical_key(
    target: Mapping[str, object],
) -> tuple[str, str]:
    if target["kind"] == "release_closure":
        path = str(target["release"]["release_path"])
    else:
        path = str(target["path"])
    physical_path = unicodedata.normalize("NFKC", path).casefold()
    return str(target["kind"]), physical_path


def _removed_targets(value: object) -> Sequence[Mapping[str, object]]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_REMOVED_TARGETS
    ):
        raise LocalReleaseIdentityError("cleanup removed_targets must be a bounded list")
    targets = [_cleanup_target(item) for item in value]
    identities = [identity_sha256(item) for item in targets]
    physical_targets = [_cleanup_target_physical_key(item) for item in targets]
    if (
        [_cleanup_target_sort_key(item) for item in targets]
        != sorted(_cleanup_target_sort_key(item) for item in targets)
    ):
        raise LocalReleaseIdentityError("cleanup removed targets must be sorted")
    if len(identities) != len(set(identities)):
        raise LocalReleaseIdentityError("cleanup removed targets must be unique")
    if len(physical_targets) != len(set(physical_targets)):
        raise LocalReleaseIdentityError(
            "cleanup removed targets repeat a physical target"
        )
    return targets


def validate_cleanup_receipt(value: object) -> Mapping[str, object]:
    receipt = _receipt_common(
        value,
        schema=CLEANUP_RECEIPT_SCHEMA,
        fields={"retained_pair", "removed_targets", "result"},
        label="cleanup receipt",
    )
    retained = _pair(
        receipt["retained_pair"],
        label="cleanup retained pair",
        allow_missing_prior=False,
    )
    removed = _removed_targets(receipt["removed_targets"])
    retained_hashes = {
        retained["active"]["manifest_sha256"],
        retained["prior"]["manifest_sha256"],
    }
    if any(
        target["kind"] == "release_closure"
        and target["release"]["manifest_sha256"] in retained_hashes
        for target in removed
    ):
        raise LocalReleaseIdentityError("cleanup cannot remove active or prior")
    result = _closed(
        receipt["result"],
        {
            "status",
            "retained_pair_sha256",
            "removed_targets_sha256",
            "removed_count",
        },
        label="cleanup result",
    )
    if (
        result["status"] != "cleaned"
        or result["retained_pair_sha256"] != _pair_hash(retained)
        or result["removed_targets_sha256"] != identity_sha256(list(removed))
        or result["removed_count"] != len(removed)
    ):
        raise LocalReleaseIdentityError("cleanup result does not bind exact targets")
    _verify_self_hash(receipt, field="receipt_sha256", label="cleanup receipt")
    return _clone(receipt, label="cleanup receipt")


_RECEIPT_VALIDATORS = {
    ACTIVATION_RECEIPT_SCHEMA: validate_activation_receipt,
    ROLLBACK_RECEIPT_SCHEMA: validate_rollback_receipt,
    FAILURE_RECEIPT_SCHEMA: validate_failure_receipt,
    CLEANUP_RECEIPT_SCHEMA: validate_cleanup_receipt,
}


def validate_local_receipt(value: object) -> Mapping[str, object]:
    receipt = _object(value, label="local receipt")
    schema = receipt.get("schema_version")
    validator = _RECEIPT_VALIDATORS.get(schema) if isinstance(schema, str) else None
    if validator is None:
        raise LocalReleaseIdentityError("local receipt schema version is unsupported")
    return validator(receipt)


def _resolve_release_ref(
    value: object,
    *,
    releases_by_hash: Mapping[str, Mapping[str, object]],
    label: str,
) -> tuple[Mapping[str, object], str]:
    reference = _release_ref(value, label=label)
    digest = str(reference["manifest_sha256"])
    release = releases_by_hash.get(digest)
    if release is None:
        raise LocalReleaseIdentityError(f"{label} references an unknown manifest hash")
    if release["release_id"] != reference["release_id"]:
        raise LocalReleaseIdentityError(f"{label} release ID/hash disagree")
    return release, digest


def _supports_state(
    release: Mapping[str, object], state_identity: Mapping[str, object], *, label: str
) -> None:
    compatibility = release["state"]["compatibility"]
    versions = state_identity["schema_versions"]
    if set(compatibility) != {*versions, "rollback_policy"}:
        raise LocalReleaseIdentityError(f"{label} state database set differs")
    for database, version in versions.items():
        contract = compatibility[database]
        if version not in contract["read"] or version not in contract["write"]:
            raise LocalReleaseIdentityError(
                f"{label} cannot read/write the bound current D state"
            )


def sealed_release_core_sha256(release: object) -> str:
    """返回 release 不可变有效载荷 core 的 canonical SHA-256。

    helper 始终先执行完整 ``qrh-release-manifest/v2`` closed-schema 校验；
    release ID、构建时间与 provenance 等发布身份字段不属于 immutable payload，
    graph linter 与部署输入能力共同复用此唯一算法。
    """

    validated = validate_release_manifest(release)
    application = validated["application"]
    if application["source_kind"] == "git":
        application_core = {
            "source_kind": "git",
            "tracked_tree_sha256": application["tracked_tree_sha256"],
        }
    else:
        application_core = {
            "source_kind": "legacy_broadcast",
            "source_archive_sha256": application["source_archive_sha256"],
        }
    content = validated["content"]
    return identity_sha256(
        {
            "application": application_core,
            "content": {
                field: content[field]
                for field in (
                    "source_inventory_sha256",
                    "ir_sha256",
                    "knowledge_sha256",
                    "search_sha256",
                    "page_projection_sha256",
                    "mcp_sha256",
                    "active_membership_sha256",
                )
            },
            "resources": {
                "inventory_sha256": validated["resources"]["inventory_sha256"]
            },
        }
    )


def _assert_acyclic(edges: Sequence[tuple[str, str]]) -> None:
    adjacency: dict[str, list[str]] = {}
    for source, target in edges:
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise LocalReleaseIdentityError("local release identity graph contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for target in adjacency[node]:
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(adjacency):
        visit(node)


def lint_local_release_graph(
    *,
    release_manifests: Sequence[object],
    active_release: object,
    local_prior_binding: object,
    retained_release_refs: Sequence[object],
    receipts: Sequence[object] = (),
) -> LocalReleaseGraphReport:
    """Mechanically close the local-only ``active -> R`` / evidence -> R graph.

    ``retained_release_refs`` is a read-only observation supplied by the future
    controller while holding its deployment lock.  It is not a second pointer.
    """

    if isinstance(release_manifests, (str, bytes)) or not isinstance(
        release_manifests, Sequence
    ):
        raise LocalReleaseIdentityError("release_manifests must be a sequence")
    releases_by_hash: dict[str, Mapping[str, object]] = {}
    releases_by_id: dict[str, str] = {}
    for raw in release_manifests:
        release = validate_release_manifest(raw)
        digest = identity_sha256(release)
        release_id = str(release["release_id"])
        if digest in releases_by_hash or release_id.casefold() in releases_by_id:
            raise LocalReleaseIdentityError("release manifest hash/ID is not unique")
        releases_by_hash[digest] = release
        releases_by_id[release_id.casefold()] = digest
    if not releases_by_hash:
        raise LocalReleaseIdentityError("release manifest set cannot be empty")

    active = validate_active_release(active_release)
    binding = validate_local_prior_binding(local_prior_binding)
    active_manifest, active_hash = _resolve_release_ref(
        active["release"], releases_by_hash=releases_by_hash, label="active current"
    )
    binding_active, binding_active_hash = _resolve_release_ref(
        binding["active"], releases_by_hash=releases_by_hash, label="binding active"
    )
    binding_prior, prior_hash = _resolve_release_ref(
        binding["prior"], releases_by_hash=releases_by_hash, label="binding prior"
    )
    if active["release"] != binding["active"] or active_hash != binding_active_hash:
        raise LocalReleaseIdentityError("active current and local-prior binding drifted")
    if sealed_release_core_sha256(
        binding_active
    ) == sealed_release_core_sha256(binding_prior):
        raise LocalReleaseIdentityError(
            "active/prior immutable payload sealed core must be genuinely distinct"
        )
    state_identity = validate_state_identity(binding["state_identity"])
    _supports_state(binding_active, state_identity, label="active release")
    _supports_state(binding_prior, state_identity, label="prior release")

    if isinstance(retained_release_refs, (str, bytes)) or not isinstance(
        retained_release_refs, Sequence
    ):
        raise LocalReleaseIdentityError("retained_release_refs must be a sequence")
    retained: list[Mapping[str, object]] = []
    retained_hashes: list[str] = []
    for index, raw in enumerate(retained_release_refs):
        _, digest = _resolve_release_ref(
            raw,
            releases_by_hash=releases_by_hash,
            label=f"retained release {index}",
        )
        retained.append(_release_ref(raw, label=f"retained release {index}"))
        retained_hashes.append(digest)
    expected_retained = [binding["active"], binding["prior"]]
    if len(retained) != 2 or {
        identity_sha256(item) for item in retained
    } != {identity_sha256(item) for item in expected_retained}:
        raise LocalReleaseIdentityError(
            "retained releases must be exactly active plus one prior"
        )

    edges: list[tuple[str, str]] = [
        ("active", f"R:{active_hash}"),
        (f"binding:{binding['binding_sha256']}", f"R:{binding_active_hash}"),
        (f"binding:{binding['binding_sha256']}", f"R:{prior_hash}"),
        (
            f"binding:{binding['binding_sha256']}",
            f"state:{state_identity['identity_sha256']}",
        ),
    ]
    receipt_ids: set[str] = set()
    terminal_attempts: dict[str, Mapping[str, object]] = {}
    cleanup_attempts: dict[str, Mapping[str, object]] = {}
    validated_receipts: list[Mapping[str, object]] = []
    if isinstance(receipts, (str, bytes)) or not isinstance(receipts, Sequence):
        raise LocalReleaseIdentityError("receipts must be a sequence")
    for raw in receipts:
        receipt = validate_local_receipt(raw)
        validated_receipts.append(receipt)
        receipt_id = str(receipt["receipt_id"])
        normalized_receipt_id = receipt_id.casefold()
        if normalized_receipt_id in receipt_ids:
            raise LocalReleaseIdentityError("receipt_id must be append-only unique")
        receipt_ids.add(normalized_receipt_id)
        node = f"receipt:{receipt['receipt_sha256']}"
        schema = receipt["schema_version"]
        attempt_id = str(receipt["attempt_id"]).casefold()
        if schema in {
            ACTIVATION_RECEIPT_SCHEMA,
            ROLLBACK_RECEIPT_SCHEMA,
            FAILURE_RECEIPT_SCHEMA,
        }:
            if attempt_id in terminal_attempts:
                raise LocalReleaseIdentityError(
                    "multiple terminal receipts exist for one attempt"
                )
            terminal_attempts[attempt_id] = receipt
            if (
                schema == ACTIVATION_RECEIPT_SCHEMA
                and receipt["operation"] == "bootstrap_first_pair"
            ):
                edges.append(
                    (
                        node,
                        "state:"
                        f"{receipt['state_identity']['identity_sha256']}",
                    )
                )
        else:
            if attempt_id in cleanup_attempts:
                raise LocalReleaseIdentityError(
                    "multiple cleanup receipts exist for one attempt"
                )
            cleanup_attempts[attempt_id] = receipt
        refs: list[Mapping[str, object]] = []
        if schema in {ACTIVATION_RECEIPT_SCHEMA, ROLLBACK_RECEIPT_SCHEMA}:
            refs.append(receipt["pair"]["active"])
            if receipt["pair"]["prior"] is not None:
                refs.append(receipt["pair"]["prior"])
        elif schema == FAILURE_RECEIPT_SCHEMA:
            original = receipt["original_pair"]
            if original["kind"] == "release_pair":
                refs.append(original["pair"]["active"])
                if original["pair"]["prior"] is not None:
                    refs.append(original["pair"]["prior"])
            refs.append(receipt["candidate"])
        elif schema == CLEANUP_RECEIPT_SCHEMA:
            retained_pair = receipt["retained_pair"]
            refs.extend((retained_pair["active"], retained_pair["prior"]))
            for target in receipt["removed_targets"]:
                if target["kind"] == "release_closure":
                    refs.append(target["release"])
                else:
                    edges.append(
                        (
                            node,
                            "cleanup:"
                            f"{target['kind']}:{identity_sha256(target)}",
                        )
                    )
        for index, reference in enumerate(refs):
            _, digest = _resolve_release_ref(
                reference,
                releases_by_hash=releases_by_hash,
                label=f"receipt {receipt_id} ref {index}",
            )
            edges.append((node, f"R:{digest}"))

    for attempt_id, cleanup in cleanup_attempts.items():
        terminal = terminal_attempts.get(attempt_id)
        if terminal is None:
            raise LocalReleaseIdentityError(
                "cleanup receipt requires a same-attempt terminal receipt"
            )
        terminal_schema = terminal["schema_version"]
        if terminal_schema == FAILURE_RECEIPT_SCHEMA:
            raise LocalReleaseIdentityError(
                "failure terminal cannot authorize cleanup receipt"
            )
        if (
            terminal_schema == ACTIVATION_RECEIPT_SCHEMA
            and terminal["operation"] == "bootstrap_first_pair"
        ):
            raise LocalReleaseIdentityError(
                "bootstrap attempt cannot have cleanup receipt"
            )
        if cleanup["retained_pair"] != terminal["pair"]:
            raise LocalReleaseIdentityError(
                "cleanup retained pair differs from same-attempt terminal result pair"
            )

    control_identities = {
        identity_sha256(active),
        str(PRODUCTION_CONTROL_ROOT / "active_release.json"),
        str(binding["binding_id"]),
        str(binding["binding_sha256"]),
        str(PRODUCTION_CONTROL_ROOT / "local_prior_binding.json"),
    }
    for receipt in validated_receipts:
        receipt_id = str(receipt["receipt_id"])
        control_identities.update(
            {
                receipt_id,
                str(receipt["receipt_sha256"]),
                str(PRODUCTION_RECEIPT_ROOT / f"{receipt_id}.json"),
            }
        )
    normalized_control_identities = {
        _normalized_control_identity(identity)
        for identity in control_identities
    }
    for release in releases_by_hash.values():
        for path, scalar in _walk_scalars(release):
            if isinstance(scalar, str) and (
                scalar in control_identities
                or _normalized_control_identity(scalar)
                in normalized_control_identities
            ):
                raise LocalReleaseIdentityError(
                    "release value references an actual deployment control identity "
                    f"at {'/'.join(path)}"
                )
        for path, sequence in _walk_string_sequences(release):
            for start in range(len(sequence)):
                joined = ""
                window_end = min(
                    len(sequence),
                    start + _MAX_CONTROL_IDENTITY_WINDOW_SEGMENTS,
                )
                for end in range(start, window_end):
                    joined += sequence[end]
                    if len(joined) > _MAX_CONTROL_IDENTITY_WINDOW_CHARACTERS:
                        break
                    if (
                        end > start
                        and _normalized_control_identity(joined)
                        in normalized_control_identities
                    ):
                        raise LocalReleaseIdentityError(
                            "release string sequence references an actual deployment "
                            f"control identity at {'/'.join(path)}"
                        )

    _assert_acyclic(edges)
    return LocalReleaseGraphReport(
        active_manifest_sha256=active_hash,
        prior_manifest_sha256=prior_hash,
        release_manifest_count=len(releases_by_hash),
        retained_release_count=len(retained_hashes),
        receipt_count=len(receipt_ids),
        edges=tuple(sorted(edges)),
    )


__all__ = [
    "ACTIVATION_RECEIPT_SCHEMA",
    "ACTIVE_RELEASE_SCHEMA",
    "CLEANUP_RECEIPT_SCHEMA",
    "FAILURE_RECEIPT_SCHEMA",
    "LOCAL_PRIOR_BINDING_SCHEMA",
    "LOCAL_STATE_IDENTITY_SCHEMA",
    "LocalReleaseGraphReport",
    "LocalReleaseIdentityError",
    "PRODUCTION_RELEASE_ROOT",
    "PRODUCTION_STATE_ROOT",
    "PRODUCTION_VM_ROOT",
    "RELEASE_MANIFEST_SCHEMA",
    "ROLLBACK_RECEIPT_SCHEMA",
    "canonical_bytes",
    "identity_sha256",
    "lint_local_release_graph",
    "sealed_release_core_sha256",
    "validate_activation_receipt",
    "validate_active_release",
    "validate_cleanup_receipt",
    "validate_failure_receipt",
    "validate_local_prior_binding",
    "validate_local_receipt",
    "validate_release_manifest",
    "validate_rollback_receipt",
    "validate_state_identity",
]
