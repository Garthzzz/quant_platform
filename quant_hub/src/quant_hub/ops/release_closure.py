"""Stage 5 release certificate 与 Stage 6 visibility closure。

本模块不运行测试、不切换 release，也不把调用者传入的布尔值提升为放行证据。
producer 只消费已经存在的 canonical gate-evidence 文件，并逐项重读其底层实际
artifact；verifier 会再次读取同一闭包。因此 certificate/receipt 只是证据闭包，
不是 active pointer、部署授权或主机／数据恢复承诺。
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Callable, Mapping, Sequence

from .local_release_identity import canonical_bytes


GATE_EVIDENCE_SCHEMA = "qrh-closure-gate-evidence/v1"
STAGE5_CERTIFICATE_SCHEMA = "qrh-stage5-release-certificate/v1"
VISIBILITY_CLOSURE_SCHEMA = "qrh-visibility-closure-receipt/v1"

EXACT_VM_PROJECT_ROOT = r"D:\quant\quant_platform"
_CONTINUITY_KIND = "active_plus_exactly_one_prior_shared_current_d_state"
_STATE_CONTRACT = "shared_current_d_state_no_restore_no_down_migration"
_REQUIRED_INTACT = (
    "production_vm",
    "exact_d_project_root",
    "active_and_exactly_one_prior_closures",
    "object_closure",
    "shared_current_d_state",
)
_OUT_OF_SCOPE = (
    "production_vm_total_loss",
    "exact_d_project_root_total_loss",
    "object_closure_total_loss",
    "shared_current_d_state_total_loss",
)

STAGE5_GATE_ROLES = (
    "full_replay_and_comment_lifecycle",
    "failure_and_incremental_matrix",
    "web_search_mcp_snapshot_consistency",
    "independent_verification",
    "shared_state_schema_compatibility",
    "active_prior_active_drill",
    "retention_closure",
    "runbook_drills_and_quality_report",
    "revocation_surface",
    "identity_graph_negative_fixtures",
)
STAGE6_GATE_ROLES = (
    "repository_private_observation",
    "private_controls_revalidation",
    "private_exact_sha_ci",
    "private_candidate_only",
    "production_identity_unchanged",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SCHEMA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,179}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ARTIFACTS = 128


class ReleaseClosureError(RuntimeError):
    """证据闭包、certificate 或 visibility receipt 无法机械验证。"""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReleaseClosureError("closure time 必须含 timezone")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReleaseClosureError(f"{label} 必须是 canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ReleaseClosureError(f"{label} 不是 ISO-8601 timestamp") from error
    if _utc_text(parsed) != value:
        raise ReleaseClosureError(f"{label} 不是 canonical UTC timestamp")
    return parsed


def _closed(value: object, fields: set[str], *, label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ReleaseClosureError(f"{label} schema 不闭合")
    return value


def _text(value: object, *, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or _CONTROL_RE.search(value)
    ):
        raise ReleaseClosureError(f"{label} 必须是非空、trimmed、无控制字符文本")
    return value


def _identifier(value: object, *, label: str) -> str:
    rendered = _text(value, label=label, maximum=180)
    if _ID_RE.fullmatch(rendered) is None or ".." in rendered:
        raise ReleaseClosureError(f"{label} 不是稳定 identifier")
    return rendered


def _schema(value: object, *, label: str) -> str:
    rendered = _text(value, label=label, maximum=180)
    if _SCHEMA_RE.fullmatch(rendered) is None or ".." in rendered:
        raise ReleaseClosureError(f"{label} 不是稳定 schema identity")
    return rendered


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ReleaseClosureError(f"{label} 必须是 lowercase SHA-256")
    if set(value) == {"0"}:
        raise ReleaseClosureError(f"{label} 不得使用 zero hash")
    return value


def _nonnegative_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReleaseClosureError(f"{label} 必须是非负整数")
    return value


def _positive_int(value: object, *, label: str) -> int:
    result = _nonnegative_int(value, label=label)
    if result == 0:
        raise ReleaseClosureError(f"{label} 必须大于零")
    return result


def _self_hash(document: Mapping[str, object], field: str, *, label: str) -> str:
    expected = _sha256(document.get(field), label=f"{label}.{field}")
    material = dict(document)
    material.pop(field, None)
    actual = hashlib.sha256(canonical_bytes(material)).hexdigest()
    if actual != expected:
        raise ReleaseClosureError(f"{label} self hash 不一致")
    return expected


def _relative_path(value: object, *, label: str) -> str:
    rendered = _text(value, label=label, maximum=1024)
    if "\\" in rendered:
        raise ReleaseClosureError(f"{label} 必须使用 canonical POSIX relative path")
    path = PurePosixPath(rendered)
    if (
        path.is_absolute()
        or rendered != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ReleaseClosureError(f"{label} 必须使用 canonical POSIX relative path")
    return rendered


def _clone(value: object, *, label: str) -> Mapping[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseClosureError(f"{label} 不是 canonical JSON material") from error
    if type(cloned) is not dict:
        raise ReleaseClosureError(f"{label} 必须是 object")
    return cloned


def _evidence_root(value: Path) -> Path:
    original = value.absolute()
    try:
        metadata = original.lstat()
    except OSError as error:
        raise ReleaseClosureError("evidence root 不存在或无法 lstat") from error
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & reparse_flag
    ):
        raise ReleaseClosureError("evidence root 必须是 ordinary directory")
    try:
        return original.resolve(strict=True)
    except OSError as error:
        raise ReleaseClosureError("evidence root 无法 canonicalize") from error


def _regular_file(root: Path, relative: str) -> Path:
    root = _evidence_root(root)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ReleaseClosureError("evidence path 逃逸或不存在") from error
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ReleaseClosureError("evidence path 无法 lstat") from error
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
            raise ReleaseClosureError("evidence path 含 symlink/reparse")
    try:
        metadata = resolved.stat()
    except OSError as error:
        raise ReleaseClosureError("evidence file 无法 stat") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ReleaseClosureError("evidence artifact 必须是 single-link regular file")
    return resolved


def _stable_file_bytes(path: Path, *, maximum_bytes: int) -> tuple[bytes, os.stat_result]:
    try:
        before = path.stat()
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise ReleaseClosureError("evidence artifact size 超出闭合边界")
        raw = path.read_bytes()
        after = path.stat()
    except OSError as error:
        raise ReleaseClosureError("evidence artifact 读取失败") from error
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(raw) != before.st_size:
        raise ReleaseClosureError("evidence artifact 在读取期间漂移")
    return raw, after


def _canonical_json_file(
    root: Path, relative: str, *, maximum_bytes: int = _MAX_JSON_BYTES
) -> tuple[Mapping[str, object], bytes]:
    path = _regular_file(root, relative)
    raw, _ = _stable_file_bytes(path, maximum_bytes=maximum_bytes)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseClosureError("evidence JSON 无法解析") from error
    document = _clone(value, label=relative)
    if raw != canonical_bytes(document):
        raise ReleaseClosureError("evidence JSON bytes 非 canonical")
    return document, raw


def _validate_release_ref(value: object, *, label: str) -> Mapping[str, object]:
    ref = _closed(
        value,
        {"release_id", "manifest_sha256", "snapshot_id"},
        label=label,
    )
    _identifier(ref["release_id"], label=f"{label}.release_id")
    _sha256(ref["manifest_sha256"], label=f"{label}.manifest_sha256")
    _identifier(ref["snapshot_id"], label=f"{label}.snapshot_id")
    return ref


def _validate_subject(value: object) -> Mapping[str, object]:
    subject = _closed(
        value,
        {"active_release", "prior_release", "state_identity_sha256"},
        label="closure subject",
    )
    active = _validate_release_ref(subject["active_release"], label="active_release")
    prior = _validate_release_ref(subject["prior_release"], label="prior_release")
    _sha256(subject["state_identity_sha256"], label="state_identity_sha256")
    if (
        active["release_id"] == prior["release_id"]
        or active["manifest_sha256"] == prior["manifest_sha256"]
    ):
        raise ReleaseClosureError("active/prior 必须是真实不同的两个 release identity")
    return subject


def _scope_document() -> Mapping[str, object]:
    return {
        "continuity_kind": _CONTINUITY_KIND,
        "exact_project_root": EXACT_VM_PROJECT_ROOT,
        "required_intact": list(_REQUIRED_INTACT),
        "retained_release_count": 2,
        "state_contract": _STATE_CONTRACT,
        "out_of_scope": list(_OUT_OF_SCOPE),
    }


def _validate_scope(value: object) -> Mapping[str, object]:
    scope = _closed(
        value,
        {
            "continuity_kind",
            "exact_project_root",
            "required_intact",
            "retained_release_count",
            "state_contract",
            "out_of_scope",
        },
        label="continuity scope",
    )
    if scope != _scope_document():
        raise ReleaseClosureError("continuity scope 扩大、缩小或漂移")
    return scope


def _expect_closed_assertions(
    value: object,
    expected: Mapping[str, object | Callable[[object], bool]],
    *,
    role: str,
) -> Mapping[str, object]:
    assertions = _closed(value, set(expected), label=f"{role}.assertions")
    for field, wanted in expected.items():
        actual = assertions[field]
        if callable(wanted):
            if not wanted(actual):
                raise ReleaseClosureError(f"{role}.{field} 未通过")
        elif type(actual) is not type(wanted) or actual != wanted:
            raise ReleaseClosureError(f"{role}.{field} 未通过")
    return assertions


def _is_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and _SHA256_RE.fullmatch(value) is not None
        and set(value) != {"0"}
    )


def _is_commit(value: object) -> bool:
    return (
        isinstance(value, str)
        and _COMMIT_RE.fullmatch(value) is not None
        and set(value) != {"0"}
    )


def _is_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and _ID_RE.fullmatch(value) is not None
        and ".." not in value
    )


_STAGE5_ASSERTIONS: Mapping[str, Mapping[str, object | Callable[[object], bool]]] = {
    "full_replay_and_comment_lifecycle": {
        "browser_result": "pass",
        "sqlite_result": "pass",
        "source_bytes_unchanged": True,
        "wrong_comment_attachments": 0,
    },
    "failure_and_incremental_matrix": {
        "failure_matrix_result": "pass",
        "silent_failures": 0,
    },
    "web_search_mcp_snapshot_consistency": {
        "snapshot_consistency_result": "pass",
        "stale_current_returns": 0,
    },
    "independent_verification": {
        "independent_verdict": "pass",
        "executor_summary_only": False,
    },
    "shared_state_schema_compatibility": {
        "candidate_read_write": "pass",
        "prior_read_write": "pass",
        "state_replaced": False,
        "down_migration_performed": False,
    },
    "active_prior_active_drill": {
        "sequence_result": "pass",
        "state_identity_unchanged": True,
        "legacy_c_writer_restarted": False,
        "outside_exact_d_project_reads": 0,
    },
    "retention_closure": {
        "retention_result": "pass",
        "retained_release_count": 2,
        "active_count": 1,
        "prior_count": 1,
        "terminal_candidates": 0,
        "completed_incoming": 0,
    },
    "runbook_drills_and_quality_report": {
        "runbook_result": "pass",
        "drill_result": "pass",
        "quality_report_result": "pass",
    },
    "revocation_surface": {
        "revocation_surface_result": "pass",
        "periodic_state_copy_tasks": 0,
        "outside_d_project_storage": 0,
        "legacy_protection_exports": 0,
    },
    "identity_graph_negative_fixtures": {
        "schema_graph_hash_result": "pass",
        "negative_fixtures_rejected": True,
    },
}


_STAGE6_ASSERTIONS: Mapping[str, Mapping[str, object | Callable[[object], bool]]] = {
    "repository_private_observation": {
        "repository_visibility": "private",
        "visibility_changed_at": lambda value: _timestamp(
            value, label="visibility_changed_at"
        )
        is not None,
    },
    "private_controls_revalidation": {
        "repository_visibility": "private",
        "actual_plan": "pass",
        "actions": "pass",
        "branch_protection": "pass",
        "environment_protection": "pass",
        "publish_minimum_permissions": "pass",
        "exact_sha_candidate_capability": "pass",
    },
    "private_exact_sha_ci": {
        "repository_visibility": "private",
        "commit_sha": _is_commit,
        "ci_conclusion": "success",
    },
    "private_candidate_only": {
        "repository_visibility": "private",
        "mode": "candidate_only",
        "production_switch": "not_performed",
        "candidate_result": "pass",
        "commit_sha": _is_commit,
        "candidate_release_id": _is_id,
        "candidate_manifest_sha256": _is_sha,
    },
    "production_identity_unchanged": {
        "repository_visibility": "private",
        "active_pointer_before_sha256": _is_sha,
        "active_pointer_after_sha256": _is_sha,
        "binding_before_sha256": _is_sha,
        "binding_after_sha256": _is_sha,
        "state_before_sha256": _is_sha,
        "state_after_sha256": _is_sha,
    },
}


def _validate_artifact_ref(
    value: object,
    *,
    root: Path,
    evidence_relative_path: str,
    evidence_observed_at: datetime,
) -> Mapping[str, object]:
    artifact = _closed(
        value,
        {
            "artifact_id",
            "relative_path",
            "artifact_kind",
            "schema_version",
            "sha256",
            "size_bytes",
            "observed_at",
        },
        label="source artifact ref",
    )
    _identifier(artifact["artifact_id"], label="artifact_id")
    relative = _relative_path(artifact["relative_path"], label="artifact.relative_path")
    if relative == evidence_relative_path:
        raise ReleaseClosureError("gate evidence 不得把自身冒充底层运行 artifact")
    kind = artifact["artifact_kind"]
    if kind not in {"canonical_json", "opaque_binary"}:
        raise ReleaseClosureError("artifact_kind 不受支持")
    if kind == "canonical_json":
        expected_schema = _schema(
            artifact["schema_version"], label="artifact.schema_version"
        )
    elif artifact["schema_version"] is not None:
        raise ReleaseClosureError("opaque artifact schema_version 必须为 null")
    else:
        expected_schema = None
    expected_hash = _sha256(artifact["sha256"], label="artifact.sha256")
    expected_size = _positive_int(artifact["size_bytes"], label="artifact.size_bytes")
    artifact_time = _timestamp(artifact["observed_at"], label="artifact.observed_at")
    if artifact_time > evidence_observed_at:
        raise ReleaseClosureError("artifact observed_at 晚于 gate evidence")
    path = _regular_file(root, relative)
    raw, metadata = _stable_file_bytes(path, maximum_bytes=_MAX_ARTIFACT_BYTES)
    if metadata.st_size != expected_size:
        raise ReleaseClosureError("artifact size 与实际文件不一致")
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ReleaseClosureError("artifact hash 与实际文件不一致")
    if kind == "canonical_json":
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleaseClosureError("canonical_json artifact 无法解析") from error
        document = _clone(parsed, label=f"artifact {relative}")
        if raw != canonical_bytes(document):
            raise ReleaseClosureError("canonical_json artifact bytes 非 canonical")
        if document.get("schema_version") != expected_schema:
            raise ReleaseClosureError("artifact schema_version 与实际文件不一致")
    return artifact


def _validate_gate_evidence(
    value: object,
    *,
    root: Path,
    relative_path: str,
    expected_roles: Sequence[str],
) -> Mapping[str, object]:
    evidence = _closed(
        value,
        {
            "schema_version",
            "evidence_id",
            "gate_role",
            "subject",
            "verdict",
            "assertions",
            "observed_at",
            "producer",
            "artifacts",
            "evidence_sha256",
        },
        label="closure gate evidence",
    )
    if evidence["schema_version"] != GATE_EVIDENCE_SCHEMA:
        raise ReleaseClosureError("gate evidence schema_version 不受支持")
    _identifier(evidence["evidence_id"], label="evidence_id")
    role = _identifier(evidence["gate_role"], label="gate_role")
    if role not in expected_roles:
        raise ReleaseClosureError("gate evidence role 不属于当前阶段")
    _validate_subject(evidence["subject"])
    if evidence["verdict"] != "pass":
        raise ReleaseClosureError("gate evidence verdict 不是 pass")
    expected_assertions = (
        _STAGE5_ASSERTIONS if role in STAGE5_GATE_ROLES else _STAGE6_ASSERTIONS
    )[role]
    _expect_closed_assertions(evidence["assertions"], expected_assertions, role=role)
    observed_at = _timestamp(evidence["observed_at"], label="evidence.observed_at")
    producer = _closed(
        evidence["producer"],
        {"name", "version", "independent"},
        label="evidence.producer",
    )
    _identifier(producer["name"], label="producer.name")
    _text(producer["version"], label="producer.version", maximum=180)
    if type(producer["independent"]) is not bool:
        raise ReleaseClosureError("producer.independent 必须是 bool")
    if role == "independent_verification" and producer["independent"] is not True:
        raise ReleaseClosureError("independent verification 必须来自独立 producer")
    artifacts = evidence["artifacts"]
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > _MAX_ARTIFACTS:
        raise ReleaseClosureError("gate evidence 必须绑定非空、有限 artifact list")
    validated = [
        _validate_artifact_ref(
            artifact,
            root=root,
            evidence_relative_path=relative_path,
            evidence_observed_at=observed_at,
        )
        for artifact in artifacts
    ]
    keys = [(item["artifact_id"], item["relative_path"]) for item in validated]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise ReleaseClosureError("artifact list 必须按 identity/path 排序且唯一")
    if not any(item["artifact_kind"] == "canonical_json" for item in validated):
        raise ReleaseClosureError("每项 gate 至少绑定一个 canonical JSON 运行结果")
    attestation_fields = {
        "gate_role": evidence["gate_role"],
        "subject": evidence["subject"],
        "verdict": evidence["verdict"],
        "assertions": evidence["assertions"],
        "observed_at": evidence["observed_at"],
        "producer": evidence["producer"],
    }
    actual_attestation = False
    for artifact in validated:
        if artifact["artifact_kind"] != "canonical_json":
            continue
        document, _ = _canonical_json_file(
            root,
            str(artifact["relative_path"]),
            maximum_bytes=_MAX_ARTIFACT_BYTES,
        )
        if all(
            field in document
            and canonical_bytes(document[field]) == canonical_bytes(expected)
            for field, expected in attestation_fields.items()
        ):
            actual_attestation = True
            break
    if not actual_attestation:
        raise ReleaseClosureError(
            "gate wrapper 的 PASS/identity/time/assertions 未被实际 canonical 运行报告逐字段绑定"
        )
    _self_hash(evidence, "evidence_sha256", label="gate evidence")
    return evidence


def _load_gate_evidence(
    root: Path, relative: str, *, expected_roles: Sequence[str]
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    relative = _relative_path(relative, label="gate evidence relative path")
    evidence, raw = _canonical_json_file(root, relative)
    validated = _validate_gate_evidence(
        evidence,
        root=root,
        relative_path=relative,
        expected_roles=expected_roles,
    )
    artifacts = validated["artifacts"]
    assert isinstance(artifacts, list)
    ref = {
        "gate_role": validated["gate_role"],
        "evidence_id": validated["evidence_id"],
        "evidence_relative_path": relative,
        "evidence_file_sha256": hashlib.sha256(raw).hexdigest(),
        "evidence_sha256": validated["evidence_sha256"],
        "observed_at": validated["observed_at"],
        "producer": validated["producer"],
        "artifact_count": len(artifacts),
        "artifact_aggregate_sha256": hashlib.sha256(canonical_bytes(artifacts)).hexdigest(),
    }
    return validated, ref


def _load_gate_set(
    root: Path,
    paths: Sequence[str],
    *,
    expected_roles: Sequence[str],
) -> tuple[tuple[Mapping[str, object], ...], tuple[Mapping[str, object], ...]]:
    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)):
        raise ReleaseClosureError("gate evidence paths 必须是 sequence")
    if len(paths) != len(expected_roles):
        raise ReleaseClosureError("gate evidence 数量不等于 required role 数量")
    loaded = [
        _load_gate_evidence(root, path, expected_roles=expected_roles) for path in paths
    ]
    documents = {str(item[0]["gate_role"]): item[0] for item in loaded}
    refs = {str(item[1]["gate_role"]): item[1] for item in loaded}
    if set(documents) != set(expected_roles) or len(documents) != len(loaded):
        raise ReleaseClosureError("gate role 缺失、重复或存在额外项")
    subjects = {canonical_bytes(item["subject"]) for item in documents.values()}
    if len(subjects) != 1:
        raise ReleaseClosureError("gate evidence subject identity 不一致")
    ordered_documents = tuple(documents[role] for role in expected_roles)
    ordered_refs = tuple(refs[role] for role in expected_roles)
    return ordered_documents, ordered_refs


def _certificate_id(subject: object, aggregate: str) -> str:
    digest = hashlib.sha256(
        canonical_bytes({"subject": subject, "evidence_aggregate_sha256": aggregate})
    ).hexdigest()
    return f"stage5-{digest[:32]}"


def produce_stage5_release_certificate(
    evidence_root: Path, evidence_paths: Sequence[str]
) -> Mapping[str, object]:
    """从 Stage 5 全部实际 gate files 生成内存 certificate。"""

    root = _evidence_root(evidence_root)
    documents, refs = _load_gate_set(root, evidence_paths, expected_roles=STAGE5_GATE_ROLES)
    # 第二次完整读取关闭 producer 自身的 artifact/namespace 观察窗口。
    documents_again, refs_again = _load_gate_set(
        root, evidence_paths, expected_roles=STAGE5_GATE_ROLES
    )
    if canonical_bytes(list(documents)) != canonical_bytes(
        list(documents_again)
    ) or canonical_bytes(list(refs)) != canonical_bytes(list(refs_again)):
        raise ReleaseClosureError("Stage 5 evidence closure 在签发前漂移")
    subject = documents[0]["subject"]
    issued_at = _utc_now()
    latest_observation = max(
        _timestamp(item["observed_at"], label="stage5 evidence observed_at")
        for item in refs
    )
    if latest_observation > issued_at:
        raise ReleaseClosureError("Stage 5 evidence observed_at 晚于签发时钟")
    aggregate = hashlib.sha256(canonical_bytes(list(refs))).hexdigest()
    certificate: dict[str, object] = {
        "schema_version": STAGE5_CERTIFICATE_SCHEMA,
        "certificate_id": _certificate_id(subject, aggregate),
        "issued_at": _utc_text(issued_at),
        "result": "pass",
        "scope": _scope_document(),
        "subject": subject,
        "evidence": list(refs),
        "evidence_aggregate_sha256": aggregate,
    }
    certificate["certificate_sha256"] = hashlib.sha256(
        canonical_bytes(certificate)
    ).hexdigest()
    return validate_stage5_release_certificate(certificate, evidence_root=root)


def validate_stage5_release_certificate(
    value: object, *, evidence_root: Path
) -> Mapping[str, object]:
    certificate = _closed(
        _clone(value, label="Stage 5 certificate"),
        {
            "schema_version",
            "certificate_id",
            "issued_at",
            "result",
            "scope",
            "subject",
            "evidence",
            "evidence_aggregate_sha256",
            "certificate_sha256",
        },
        label="Stage 5 certificate",
    )
    if certificate["schema_version"] != STAGE5_CERTIFICATE_SCHEMA:
        raise ReleaseClosureError("Stage 5 certificate schema_version 不受支持")
    _identifier(certificate["certificate_id"], label="certificate_id")
    issued_at = _timestamp(certificate["issued_at"], label="certificate.issued_at")
    if certificate["result"] != "pass":
        raise ReleaseClosureError("Stage 5 certificate result 不是 pass")
    _validate_scope(certificate["scope"])
    subject = _validate_subject(certificate["subject"])
    evidence = certificate["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(STAGE5_GATE_ROLES):
        raise ReleaseClosureError("Stage 5 certificate evidence 不完整")
    paths: list[str] = []
    for expected_role, ref in zip(STAGE5_GATE_ROLES, evidence, strict=True):
        closed_ref = _closed(
            ref,
            {
                "gate_role",
                "evidence_id",
                "evidence_relative_path",
                "evidence_file_sha256",
                "evidence_sha256",
                "observed_at",
                "producer",
                "artifact_count",
                "artifact_aggregate_sha256",
            },
            label="Stage 5 evidence ref",
        )
        if closed_ref["gate_role"] != expected_role:
            raise ReleaseClosureError("Stage 5 evidence 顺序或 role 漂移")
        paths.append(
            _relative_path(
                closed_ref["evidence_relative_path"], label="evidence_relative_path"
            )
        )
        _sha256(closed_ref["evidence_file_sha256"], label="evidence_file_sha256")
        _sha256(closed_ref["evidence_sha256"], label="evidence_sha256")
        _sha256(
            closed_ref["artifact_aggregate_sha256"],
            label="artifact_aggregate_sha256",
        )
        _positive_int(closed_ref["artifact_count"], label="artifact_count")
        if _timestamp(closed_ref["observed_at"], label="evidence observed_at") > issued_at:
            raise ReleaseClosureError("Stage 5 evidence 晚于 certificate")
    actual_documents, actual_refs = _load_gate_set(
        _evidence_root(evidence_root), paths, expected_roles=STAGE5_GATE_ROLES
    )
    actual_documents_again, actual_refs_again = _load_gate_set(
        _evidence_root(evidence_root), paths, expected_roles=STAGE5_GATE_ROLES
    )
    if canonical_bytes(list(actual_documents)) != canonical_bytes(
        list(actual_documents_again)
    ) or canonical_bytes(list(actual_refs)) != canonical_bytes(list(actual_refs_again)):
        raise ReleaseClosureError("Stage 5 evidence closure 在核验期间漂移")
    if canonical_bytes(evidence) != canonical_bytes(list(actual_refs)):
        raise ReleaseClosureError("Stage 5 certificate evidence file closure 漂移")
    if canonical_bytes(subject) != canonical_bytes(actual_documents[0]["subject"]):
        raise ReleaseClosureError("Stage 5 certificate subject 与 evidence 不一致")
    aggregate = _sha256(
        certificate["evidence_aggregate_sha256"], label="evidence_aggregate_sha256"
    )
    if hashlib.sha256(canonical_bytes(evidence)).hexdigest() != aggregate:
        raise ReleaseClosureError("Stage 5 evidence aggregate 不一致")
    if certificate["certificate_id"] != _certificate_id(subject, aggregate):
        raise ReleaseClosureError("Stage 5 certificate_id 不一致")
    _self_hash(certificate, "certificate_sha256", label="Stage 5 certificate")
    return certificate


def verify_stage5_release_certificate_file(
    evidence_root: Path, certificate_relative_path: str
) -> Mapping[str, object]:
    relative = _relative_path(certificate_relative_path, label="certificate path")
    root = _evidence_root(evidence_root)
    document, raw = _canonical_json_file(root, relative)
    verified = validate_stage5_release_certificate(document, evidence_root=root)
    document_again, raw_again = _canonical_json_file(root, relative)
    if raw != raw_again or canonical_bytes(verified) != canonical_bytes(document_again):
        raise ReleaseClosureError("Stage 5 certificate 在核验期间漂移")
    return verified


def _stage5_certificate_ref(
    root: Path, relative: str
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    relative = _relative_path(relative, label="Stage 5 certificate path")
    document, raw = _canonical_json_file(root, relative)
    certificate = validate_stage5_release_certificate(document, evidence_root=root)
    document_again, raw_again = _canonical_json_file(root, relative)
    if raw != raw_again or canonical_bytes(certificate) != canonical_bytes(document_again):
        raise ReleaseClosureError("Stage 5 certificate 在 closure 读取期间漂移")
    return certificate, {
        "certificate_id": certificate["certificate_id"],
        "certificate_relative_path": relative,
        "certificate_file_sha256": hashlib.sha256(raw).hexdigest(),
        "certificate_sha256": certificate["certificate_sha256"],
        "issued_at": certificate["issued_at"],
    }


def _validate_stage6_semantics(
    documents: Sequence[Mapping[str, object]], *, certificate_issued_at: datetime
) -> tuple[str, str, str]:
    by_role = {str(item["gate_role"]): item for item in documents}
    for document in documents:
        observed = _timestamp(document["observed_at"], label="Stage 6 observed_at")
        if observed <= certificate_issued_at:
            raise ReleaseClosureError("Stage 6 evidence 必须晚于 Stage 5 certificate")
    visibility = by_role["repository_private_observation"]["assertions"]
    assert isinstance(visibility, Mapping)
    visibility_changed_at = _timestamp(
        visibility["visibility_changed_at"], label="visibility_changed_at"
    )
    if visibility_changed_at <= certificate_issued_at:
        raise ReleaseClosureError("Public→Private 发生在 Stage 5 certificate 之前")
    ci = by_role["private_exact_sha_ci"]["assertions"]
    candidate = by_role["private_candidate_only"]["assertions"]
    unchanged = by_role["production_identity_unchanged"]["assertions"]
    assert isinstance(ci, Mapping)
    assert isinstance(candidate, Mapping)
    assert isinstance(unchanged, Mapping)
    if ci["commit_sha"] != candidate["commit_sha"]:
        raise ReleaseClosureError("Private CI 与 candidate-only 不是 exact same SHA")
    for prefix in ("active_pointer", "binding", "state"):
        if unchanged[f"{prefix}_before_sha256"] != unchanged[f"{prefix}_after_sha256"]:
            raise ReleaseClosureError("Private candidate-only 改变了生产 pointer/binding/state")
    return (
        str(ci["commit_sha"]),
        str(candidate["candidate_release_id"]),
        str(candidate["candidate_manifest_sha256"]),
    )


def produce_visibility_closure_receipt(
    evidence_root: Path,
    *,
    stage5_certificate_path: str,
    evidence_paths: Sequence[str],
) -> Mapping[str, object]:
    """仅在 Stage 5 certificate 后的 Private 复验闭合时生成 receipt。"""

    root = _evidence_root(evidence_root)
    certificate, certificate_ref = _stage5_certificate_ref(root, stage5_certificate_path)
    documents, refs = _load_gate_set(root, evidence_paths, expected_roles=STAGE6_GATE_ROLES)
    certificate_again, certificate_ref_again = _stage5_certificate_ref(
        root, stage5_certificate_path
    )
    documents_again, refs_again = _load_gate_set(
        root, evidence_paths, expected_roles=STAGE6_GATE_ROLES
    )
    if (
        canonical_bytes(certificate) != canonical_bytes(certificate_again)
        or canonical_bytes(certificate_ref) != canonical_bytes(certificate_ref_again)
        or canonical_bytes(list(documents)) != canonical_bytes(list(documents_again))
        or canonical_bytes(list(refs)) != canonical_bytes(list(refs_again))
    ):
        raise ReleaseClosureError("visibility closure 在签发前漂移")
    if canonical_bytes(documents[0]["subject"]) != canonical_bytes(certificate["subject"]):
        raise ReleaseClosureError("Stage 6 evidence subject 与 Stage 5 certificate 不一致")
    issued_at = _utc_now()
    certificate_time = _timestamp(certificate["issued_at"], label="certificate issued_at")
    commit_sha, candidate_release_id, candidate_manifest_sha256 = _validate_stage6_semantics(
        documents, certificate_issued_at=certificate_time
    )
    if max(
        _timestamp(item["observed_at"], label="Stage 6 observed_at") for item in refs
    ) > issued_at:
        raise ReleaseClosureError("Stage 6 evidence observed_at 晚于签发时钟")
    aggregate = hashlib.sha256(canonical_bytes(list(refs))).hexdigest()
    receipt_id_material = {
        "stage5_certificate_sha256": certificate["certificate_sha256"],
        "private_commit_sha": commit_sha,
        "evidence_aggregate_sha256": aggregate,
    }
    receipt: dict[str, object] = {
        "schema_version": VISIBILITY_CLOSURE_SCHEMA,
        "receipt_id": "visibility-"
        + hashlib.sha256(canonical_bytes(receipt_id_material)).hexdigest()[:32],
        "issued_at": _utc_text(issued_at),
        "result": "pass",
        "repository_visibility": "private",
        "scope": _scope_document(),
        "subject": certificate["subject"],
        "stage5_certificate": certificate_ref,
        "private_commit_sha": commit_sha,
        "candidate_only": {
            "release_id": candidate_release_id,
            "manifest_sha256": candidate_manifest_sha256,
            "production_switch": "not_performed",
        },
        "evidence": list(refs),
        "evidence_aggregate_sha256": aggregate,
    }
    receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return validate_visibility_closure_receipt(receipt, evidence_root=root)


def validate_visibility_closure_receipt(
    value: object, *, evidence_root: Path
) -> Mapping[str, object]:
    receipt = _closed(
        _clone(value, label="visibility closure receipt"),
        {
            "schema_version",
            "receipt_id",
            "issued_at",
            "result",
            "repository_visibility",
            "scope",
            "subject",
            "stage5_certificate",
            "private_commit_sha",
            "candidate_only",
            "evidence",
            "evidence_aggregate_sha256",
            "receipt_sha256",
        },
        label="visibility closure receipt",
    )
    if receipt["schema_version"] != VISIBILITY_CLOSURE_SCHEMA:
        raise ReleaseClosureError("visibility receipt schema_version 不受支持")
    _identifier(receipt["receipt_id"], label="receipt_id")
    issued_at = _timestamp(receipt["issued_at"], label="receipt.issued_at")
    if receipt["result"] != "pass" or receipt["repository_visibility"] != "private":
        raise ReleaseClosureError("visibility closure 尚未 PASS/private")
    _validate_scope(receipt["scope"])
    subject = _validate_subject(receipt["subject"])
    certificate_ref = _closed(
        receipt["stage5_certificate"],
        {
            "certificate_id",
            "certificate_relative_path",
            "certificate_file_sha256",
            "certificate_sha256",
            "issued_at",
        },
        label="Stage 5 certificate ref",
    )
    certificate, actual_certificate_ref = _stage5_certificate_ref(
        _evidence_root(evidence_root),
        _relative_path(
            certificate_ref["certificate_relative_path"], label="certificate path"
        ),
    )
    if canonical_bytes(certificate_ref) != canonical_bytes(actual_certificate_ref):
        raise ReleaseClosureError("Stage 5 certificate file closure 漂移")
    if canonical_bytes(subject) != canonical_bytes(certificate["subject"]):
        raise ReleaseClosureError("visibility subject 与 Stage 5 certificate 不一致")
    certificate_time = _timestamp(certificate["issued_at"], label="certificate issued_at")
    if issued_at <= certificate_time:
        raise ReleaseClosureError("visibility receipt 必须晚于 Stage 5 certificate")
    evidence = receipt["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(STAGE6_GATE_ROLES):
        raise ReleaseClosureError("Stage 6 evidence 不完整")
    paths: list[str] = []
    for expected_role, ref in zip(STAGE6_GATE_ROLES, evidence, strict=True):
        closed_ref = _closed(
            ref,
            {
                "gate_role",
                "evidence_id",
                "evidence_relative_path",
                "evidence_file_sha256",
                "evidence_sha256",
                "observed_at",
                "producer",
                "artifact_count",
                "artifact_aggregate_sha256",
            },
            label="Stage 6 evidence ref",
        )
        if closed_ref["gate_role"] != expected_role:
            raise ReleaseClosureError("Stage 6 evidence 顺序或 role 漂移")
        paths.append(
            _relative_path(
                closed_ref["evidence_relative_path"], label="evidence_relative_path"
            )
        )
        if _timestamp(closed_ref["observed_at"], label="Stage 6 observed_at") > issued_at:
            raise ReleaseClosureError("Stage 6 evidence 晚于 visibility receipt")
    documents, actual_refs = _load_gate_set(
        _evidence_root(evidence_root), paths, expected_roles=STAGE6_GATE_ROLES
    )
    documents_again, actual_refs_again = _load_gate_set(
        _evidence_root(evidence_root), paths, expected_roles=STAGE6_GATE_ROLES
    )
    if canonical_bytes(list(documents)) != canonical_bytes(
        list(documents_again)
    ) or canonical_bytes(list(actual_refs)) != canonical_bytes(list(actual_refs_again)):
        raise ReleaseClosureError("Stage 6 evidence closure 在核验期间漂移")
    if canonical_bytes(evidence) != canonical_bytes(list(actual_refs)):
        raise ReleaseClosureError("Stage 6 evidence file closure 漂移")
    commit_sha, candidate_release_id, candidate_manifest_sha256 = _validate_stage6_semantics(
        documents, certificate_issued_at=certificate_time
    )
    if canonical_bytes(documents[0]["subject"]) != canonical_bytes(subject):
        raise ReleaseClosureError("Stage 6 evidence subject 不一致")
    if receipt["private_commit_sha"] != commit_sha:
        raise ReleaseClosureError("visibility private commit 漂移")
    candidate = _closed(
        receipt["candidate_only"],
        {"release_id", "manifest_sha256", "production_switch"},
        label="candidate_only result",
    )
    if candidate != {
        "release_id": candidate_release_id,
        "manifest_sha256": candidate_manifest_sha256,
        "production_switch": "not_performed",
    }:
        raise ReleaseClosureError("candidate-only identity/result 漂移")
    aggregate = _sha256(
        receipt["evidence_aggregate_sha256"], label="evidence_aggregate_sha256"
    )
    if hashlib.sha256(canonical_bytes(evidence)).hexdigest() != aggregate:
        raise ReleaseClosureError("Stage 6 evidence aggregate 不一致")
    expected_id = "visibility-" + hashlib.sha256(
        canonical_bytes(
            {
                "stage5_certificate_sha256": certificate["certificate_sha256"],
                "private_commit_sha": commit_sha,
                "evidence_aggregate_sha256": aggregate,
            }
        )
    ).hexdigest()[:32]
    if receipt["receipt_id"] != expected_id:
        raise ReleaseClosureError("visibility receipt_id 不一致")
    _self_hash(receipt, "receipt_sha256", label="visibility closure receipt")
    return receipt


def verify_visibility_closure_receipt_file(
    evidence_root: Path, receipt_relative_path: str
) -> Mapping[str, object]:
    relative = _relative_path(receipt_relative_path, label="visibility receipt path")
    root = _evidence_root(evidence_root)
    document, raw = _canonical_json_file(root, relative)
    verified = validate_visibility_closure_receipt(document, evidence_root=root)
    document_again, raw_again = _canonical_json_file(root, relative)
    if raw != raw_again or canonical_bytes(verified) != canonical_bytes(document_again):
        raise ReleaseClosureError("visibility receipt 在核验期间漂移")
    return verified


def _create_canonical_file(root: Path, relative: str, value: object) -> Path:
    relative = _relative_path(relative, label="closure output path")
    root = _evidence_root(root)
    target = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ReleaseClosureError("closure output parent 不存在") from error
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or attributes & reparse_flag
        ):
            raise ReleaseClosureError("closure output parent 含 symlink/reparse")
    try:
        target.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise ReleaseClosureError("closure output parent 不存在或逃逸") from error
    if target.exists() or target.is_symlink():
        raise ReleaseClosureError("closure output 已存在；证书/收据不可覆盖")
    raw = canonical_bytes(value)
    try:
        with target.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise ReleaseClosureError("closure output create-only 写入失败") from error
    if target.read_bytes() != raw:
        raise ReleaseClosureError("closure output 回读不一致")
    return target


def write_stage5_release_certificate(
    evidence_root: Path, evidence_paths: Sequence[str], *, output_path: str
) -> Mapping[str, object]:
    certificate = produce_stage5_release_certificate(evidence_root, evidence_paths)
    _create_canonical_file(evidence_root, output_path, certificate)
    return verify_stage5_release_certificate_file(evidence_root, output_path)


def write_visibility_closure_receipt(
    evidence_root: Path,
    *,
    stage5_certificate_path: str,
    evidence_paths: Sequence[str],
    output_path: str,
) -> Mapping[str, object]:
    receipt = produce_visibility_closure_receipt(
        evidence_root,
        stage5_certificate_path=stage5_certificate_path,
        evidence_paths=evidence_paths,
    )
    _create_canonical_file(evidence_root, output_path, receipt)
    return verify_visibility_closure_receipt_file(evidence_root, output_path)


def vm_origin_path(relative_path: str) -> str:
    """把闭包相对路径转换为证书展示用 exact-D canonical Windows path。"""

    relative = _relative_path(relative_path, label="VM origin path")
    return str(PureWindowsPath(EXACT_VM_PROJECT_ROOT).joinpath(*PurePosixPath(relative).parts))
