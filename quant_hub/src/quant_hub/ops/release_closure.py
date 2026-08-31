"""Stage 5 release certificate 与 Stage 6 visibility closure。

本模块不运行测试、不切换 release，也不把调用者传入的布尔值、managed wrapper、
self-hash 或 exit code 提升为放行证据。CLI 只消费 exact D 根内的 canonical artifact，
从实际 active/binding/manifests 重建 subject，并要求每个角色具有可重放的真实分类
adapter；adapter 缺失时无条件 non-qualifying。因此 certificate/receipt 只是证据闭包，
不是 active pointer、部署授权或主机／数据恢复承诺。
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import sys
from typing import Callable, Mapping, Sequence

from .local_release_identity import (
    ACTIVE_RELEASE_SCHEMA,
    LOCAL_PRIOR_BINDING_SCHEMA,
    RELEASE_MANIFEST_SCHEMA,
    LocalReleaseIdentityError,
    canonical_bytes,
    identity_sha256,
    validate_active_release,
    validate_local_prior_binding,
    validate_release_manifest,
)
from .identity_graph_fixture import (
    CORPUS_SCHEMA as IDENTITY_GRAPH_CORPUS_SCHEMA,
    GATE_ROLE as IDENTITY_GRAPH_GATE_ROLE,
    PRODUCER_NAME as IDENTITY_GRAPH_PRODUCER_NAME,
    PRODUCER_VERSION as IDENTITY_GRAPH_PRODUCER_VERSION,
    REPORT_AUTHORITY_SCOPE as IDENTITY_GRAPH_REPORT_AUTHORITY_SCOPE,
    REPORT_SCHEMA as IDENTITY_GRAPH_REPORT_SCHEMA,
    IdentityGraphFixtureError,
    artifact_input_aggregate_sha256,
    fixed_corpus_document,
    replay_fixed_corpus,
)
GATE_EVIDENCE_SCHEMA = "qrh-closure-gate-evidence/v2-managed-inputs"
GATE_OBSERVATION_SCHEMA = "qrh-closure-gate-observation/v2-managed-inputs"
STAGE5_CERTIFICATE_SCHEMA = "qrh-stage5-release-certificate/v1"
VISIBILITY_CLOSURE_SCHEMA = "qrh-visibility-closure-receipt/v1"

EXACT_VM_PROJECT_ROOT = r"D:\quant\quant_platform"
_CONTINUITY_KIND = "active_plus_exactly_one_prior_shared_current_d_state"
_STATE_CONTRACT = "shared_current_d_state_no_restore_no_down_migration"
_REAL_MCP_ACCEPTANCE_AUTHORITY = "AUTHORITATIVE_REAL_CODEX_INTEGRATED_GATE"
_REAL_MCP_CAMPAIGN_SCHEMA = "qrh-mcp-acceptance-campaign-receipt/v3-dispatch-replay"
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

_MANAGED_RESULT_SCHEMAS = {
    role: f"qrh-closure-{role.replace('_', '-')}-result/v1"
    for role in (*STAGE5_GATE_ROLES, *STAGE6_GATE_ROLES)
}
_PRIMARY_RESULT_SCHEMAS = {
    **_MANAGED_RESULT_SCHEMAS,
    IDENTITY_GRAPH_GATE_ROLE: IDENTITY_GRAPH_REPORT_SCHEMA,
}
_STAGE5_MACHINE_AUTHORITY = "QRH_STAGE5_MANAGED_MACHINE_OBSERVER"
_INDEPENDENT_AUTHORITY = "QRH_STAGE5_INDEPENDENT_VERIFIER_DISPATCH"
_GITHUB_AUTHORITY = "QRH_STAGE6_GITHUB_API_OBSERVER"
_PRIVATE_CANDIDATE_AUTHORITY = "QRH_STAGE6_PRIVATE_CANDIDATE_OBSERVER"
_MANAGED_AUTHORITIES = {
    **{
        role: _STAGE5_MACHINE_AUTHORITY
        for role in STAGE5_GATE_ROLES
        if role != "independent_verification"
    },
    "independent_verification": _INDEPENDENT_AUTHORITY,
    "repository_private_observation": _GITHUB_AUTHORITY,
    "private_controls_revalidation": _GITHUB_AUTHORITY,
    "private_exact_sha_ci": _GITHUB_AUTHORITY,
    "private_candidate_only": _PRIVATE_CANDIDATE_AUTHORITY,
    "production_identity_unchanged": _PRIVATE_CANDIDATE_AUTHORITY,
}
_MANAGED_OBSERVER_NAMES = {
    _STAGE5_MACHINE_AUTHORITY: "qrh-stage5-machine-observer",
    _INDEPENDENT_AUTHORITY: "qrh-independent-stage5-verifier",
    _GITHUB_AUTHORITY: "qrh-github-api-observer",
    _PRIVATE_CANDIDATE_AUTHORITY: "qrh-private-candidate-observer",
}
_REQUIRED_REAL_GATE_ADAPTERS: Mapping[str, tuple[str, str]] = {
    "full_replay_and_comment_lifecycle": (
        "qrh-stage5-browser-sqlite-comment-replay-receipt/v1",
        "browser + SQLite + source inventory replay verifier",
    ),
    "failure_and_incremental_matrix": (
        "qrh-stage5-failure-incremental-machine-report/v1",
        "failure/incremental matrix report replay verifier",
    ),
    "web_search_mcp_snapshot_consistency": (
        "qrh-stage5-web-search-mcp-snapshot-replay-receipt/v1",
        "snapshot/continuation replay verifier plus real MCP campaign verifier",
    ),
    "independent_verification": (
        "qrh-stage5-independent-dispatch-verification-receipt/v1",
        "independent dispatch ledger and input-closure verifier",
    ),
    "shared_state_schema_compatibility": (
        "qrh-stage5-shared-state-compatibility-replay-receipt/v1",
        "candidate/prior SQLite CAS/event compatibility verifier",
    ),
    "active_prior_active_drill": (
        "qrh-stage5-active-prior-active-vm-drill-receipt/v1",
        "activation/rollback receipt and VM read/write-set replay verifier",
    ),
    "retention_closure": (
        "qrh-stage5-retention-filesystem-audit-receipt/v1",
        "active/prior/incoming/object closure filesystem verifier",
    ),
    "runbook_drills_and_quality_report": (
        "qrh-stage5-runbook-drill-quality-receipt/v1",
        "runbook artifact and drill/quality report verifier",
    ),
    "revocation_surface": (
        "qrh-stage5-revocation-machine-audit-receipt/v1",
        "source/wheel/config/task/write-set audit verifier",
    ),
    "identity_graph_negative_fixtures": (
        "qrh-stage5-identity-graph-fixture-report/v1",
        "identity graph fixture replay verifier",
    ),
    "repository_private_observation": (
        "qrh-stage6-github-repository-api-capture/v1",
        "authenticated GitHub repository response verifier",
    ),
    "private_controls_revalidation": (
        "qrh-stage6-github-controls-api-capture/v1",
        "authenticated plan/Actions/protection/permission response verifier",
    ),
    "private_exact_sha_ci": (
        "qrh-stage6-github-exact-sha-ci-api-capture/v1",
        "authenticated exact-SHA workflow/check-run response verifier",
    ),
    "private_candidate_only": (
        "qrh-stage6-private-candidate-machine-receipt/v1",
        "candidate receipt and zero production-switch verifier",
    ),
    "production_identity_unchanged": (
        "qrh-stage6-production-identity-capture/v1",
        "before/after active/binding/state byte verifier",
    ),
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_SCHEMA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,179}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
_MAX_ARTIFACTS = 128
_MAX_MCP_CAMPAIGN_FILE_BYTES = 64 * 1024 * 1024
_MAX_MCP_CAMPAIGN_TOTAL_BYTES = 512 * 1024 * 1024


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


def _ordinary_directory(root: Path, relative: str) -> Path:
    root = _evidence_root(root)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ReleaseClosureError("evidence directory 逃逸或不存在") from error
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ReleaseClosureError("evidence directory 无法 lstat") from error
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or attributes & reparse_flag
        ):
            raise ReleaseClosureError("evidence directory 含 symlink/reparse 或非目录")
    return resolved


def _stable_file_bytes(path: Path, *, maximum_bytes: int) -> tuple[bytes, os.stat_result]:
    try:
        path_before = path.lstat()
        attributes = int(getattr(path_before, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if (
            not stat.S_ISREG(path_before.st_mode)
            or stat.S_ISLNK(path_before.st_mode)
            or attributes & reparse_flag
            or path_before.st_nlink != 1
            or path.resolve(strict=True) != path
        ):
            raise ReleaseClosureError("evidence artifact 在打开前不是 ordinary file")
        if path_before.st_size <= 0 or path_before.st_size > maximum_bytes:
            raise ReleaseClosureError("evidence artifact size 超出闭合边界")
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            raw = handle.read(maximum_bytes + 1)
            after = os.fstat(handle.fileno())
        path_after = path.lstat()
        resolved_after = path.resolve(strict=True)
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
    path_identity_before = (
        path_before.st_dev,
        path_before.st_ino,
        path_before.st_size,
        path_before.st_mtime_ns,
        path_before.st_ctime_ns,
    )
    path_identity_after = (
        path_after.st_dev,
        path_after.st_ino,
        path_after.st_size,
        path_after.st_mtime_ns,
        path_after.st_ctime_ns,
    )
    handle_path_key = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    lstat_path_key = (
        path_before.st_dev,
        path_before.st_ino,
        path_before.st_size,
        path_before.st_mtime_ns,
    )
    if (
        identity_before != identity_after
        or path_identity_before != path_identity_after
        or handle_path_key != lstat_path_key
        or len(raw) != before.st_size
        or len(raw) > maximum_bytes
        or resolved_after != path
    ):
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
        "mcp_acceptance_status": "PASS",
        "mcp_acceptance_authority": _REAL_MCP_ACCEPTANCE_AUTHORITY,
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


def _count(value: object, *, label: str, positive: bool = False) -> int:
    return (
        _positive_int(value, label=label)
        if positive
        else _nonnegative_int(value, label=label)
    )


def _complete_count_pair(
    facts: Mapping[str, object], *, total: str, passed: str, role: str
) -> None:
    total_value = _count(facts[total], label=f"{role}.facts.{total}", positive=True)
    passed_value = _count(facts[passed], label=f"{role}.facts.{passed}")
    if passed_value != total_value:
        raise ReleaseClosureError(f"{role}.{passed} 未覆盖全部 {total}")


def _same_sha_pair(
    facts: Mapping[str, object], *, before: str, after: str, role: str
) -> None:
    before_value = _sha256(facts[before], label=f"{role}.facts.{before}")
    after_value = _sha256(facts[after], label=f"{role}.facts.{after}")
    if before_value != after_value:
        raise ReleaseClosureError(f"{role}.{before}/{after} 发生漂移")


def _id_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ReleaseClosureError(f"{label} 必须是 identifier list")
    rendered = [_identifier(item, label=label) for item in value]
    if rendered != sorted(rendered) or len(rendered) != len(set(rendered)):
        raise ReleaseClosureError(f"{label} 必须按字典序排序且唯一")
    return rendered


def _derive_stage5_assertions(
    role: str,
    facts_value: object,
    *,
    independent: bool,
    mcp_acceptance: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    """从无 verdict/status 字段的现场事实机械派生 Stage 5 断言。"""

    if role == "full_replay_and_comment_lifecycle":
        facts = _closed(
            facts_value,
            {
                "browser_checks_total",
                "browser_checks_passed",
                "sqlite_checks_total",
                "sqlite_checks_passed",
                "source_bytes_before_sha256",
                "source_bytes_after_sha256",
                "wrong_comment_attachments",
            },
            label=f"{role}.facts",
        )
        _complete_count_pair(
            facts,
            total="browser_checks_total",
            passed="browser_checks_passed",
            role=role,
        )
        _complete_count_pair(
            facts,
            total="sqlite_checks_total",
            passed="sqlite_checks_passed",
            role=role,
        )
        _same_sha_pair(
            facts,
            before="source_bytes_before_sha256",
            after="source_bytes_after_sha256",
            role=role,
        )
        wrong = _count(
            facts["wrong_comment_attachments"],
            label=f"{role}.facts.wrong_comment_attachments",
        )
        if wrong:
            raise ReleaseClosureError(f"{role}.wrong_comment_attachments 非零")
        result = {
            "browser_result": "pass",
            "sqlite_result": "pass",
            "source_bytes_unchanged": True,
            "wrong_comment_attachments": 0,
        }
    elif role == "failure_and_incremental_matrix":
        facts = _closed(
            facts_value,
            {"matrix_cases_total", "matrix_cases_passed", "silent_failures"},
            label=f"{role}.facts",
        )
        _complete_count_pair(
            facts,
            total="matrix_cases_total",
            passed="matrix_cases_passed",
            role=role,
        )
        if _count(facts["silent_failures"], label=f"{role}.facts.silent_failures"):
            raise ReleaseClosureError(f"{role}.silent_failures 非零")
        result = {"failure_matrix_result": "pass", "silent_failures": 0}
    elif role == "web_search_mcp_snapshot_consistency":
        facts = _closed(
            facts_value,
            {
                "snapshot_checks_total",
                "snapshot_checks_passed",
                "stale_current_returns",
                "mcp_acceptance_evidence_root",
            },
            label=f"{role}.facts",
        )
        _relative_path(
            facts["mcp_acceptance_evidence_root"],
            label=f"{role}.facts.mcp_acceptance_evidence_root",
        )
        _complete_count_pair(
            facts,
            total="snapshot_checks_total",
            passed="snapshot_checks_passed",
            role=role,
        )
        if _count(
            facts["stale_current_returns"], label=f"{role}.facts.stale_current_returns"
        ):
            raise ReleaseClosureError(f"{role}.stale_current_returns 非零")
        if (
            mcp_acceptance is None
            or mcp_acceptance.get("status") != "PASS"
            or mcp_acceptance.get("authority") != _REAL_MCP_ACCEPTANCE_AUTHORITY
        ):
            raise ReleaseClosureError("MCP acceptance 不是 authoritative real-Codex PASS")
        result = {
            "snapshot_consistency_result": "pass",
            "stale_current_returns": 0,
            "mcp_acceptance_status": "PASS",
            "mcp_acceptance_authority": _REAL_MCP_ACCEPTANCE_AUTHORITY,
        }
    elif role == "independent_verification":
        facts = _closed(
            facts_value,
            {
                "inspected_artifacts",
                "p0_findings",
                "p1_findings",
                "p2_findings",
                "executor_summary_inputs",
            },
            label=f"{role}.facts",
        )
        if not independent:
            raise ReleaseClosureError("independent verification observer 必须独立")
        _count(
            facts["inspected_artifacts"],
            label=f"{role}.facts.inspected_artifacts",
            positive=True,
        )
        for field in ("p0_findings", "p1_findings", "p2_findings", "executor_summary_inputs"):
            if _count(facts[field], label=f"{role}.facts.{field}"):
                raise ReleaseClosureError(f"{role}.{field} 非零")
        result = {"independent_verdict": "pass", "executor_summary_only": False}
    elif role == "shared_state_schema_compatibility":
        fields = {
            "candidate_checks_total",
            "candidate_checks_passed",
            "prior_checks_total",
            "prior_checks_passed",
            "state_before_sha256",
            "state_after_sha256",
            "down_migration_count",
        }
        facts = _closed(facts_value, fields, label=f"{role}.facts")
        _complete_count_pair(
            facts,
            total="candidate_checks_total",
            passed="candidate_checks_passed",
            role=role,
        )
        _complete_count_pair(
            facts,
            total="prior_checks_total",
            passed="prior_checks_passed",
            role=role,
        )
        _same_sha_pair(
            facts, before="state_before_sha256", after="state_after_sha256", role=role
        )
        if _count(
            facts["down_migration_count"], label=f"{role}.facts.down_migration_count"
        ):
            raise ReleaseClosureError(f"{role}.down_migration_count 非零")
        result = {
            "candidate_read_write": "pass",
            "prior_read_write": "pass",
            "state_replaced": False,
            "down_migration_performed": False,
        }
    elif role == "active_prior_active_drill":
        facts = _closed(
            facts_value,
            {
                "transition_sequence",
                "transition_checks_total",
                "transition_checks_passed",
                "state_before_sha256",
                "state_after_sha256",
                "legacy_c_writer_restart_count",
                "outside_exact_d_project_reads",
            },
            label=f"{role}.facts",
        )
        if facts["transition_sequence"] != ["active", "prior", "active"]:
            raise ReleaseClosureError(f"{role}.transition_sequence 不闭合")
        _complete_count_pair(
            facts,
            total="transition_checks_total",
            passed="transition_checks_passed",
            role=role,
        )
        _same_sha_pair(
            facts, before="state_before_sha256", after="state_after_sha256", role=role
        )
        for field in ("legacy_c_writer_restart_count", "outside_exact_d_project_reads"):
            if _count(facts[field], label=f"{role}.facts.{field}"):
                raise ReleaseClosureError(f"{role}.{field} 非零")
        result = {
            "sequence_result": "pass",
            "state_identity_unchanged": True,
            "legacy_c_writer_restarted": False,
            "outside_exact_d_project_reads": 0,
        }
    elif role == "retention_closure":
        facts = _closed(
            facts_value,
            {
                "active_release_id",
                "prior_release_id",
                "retained_release_ids",
                "terminal_candidate_ids",
                "completed_incoming_ids",
            },
            label=f"{role}.facts",
        )
        active = _identifier(facts["active_release_id"], label=f"{role}.active_release_id")
        prior = _identifier(facts["prior_release_id"], label=f"{role}.prior_release_id")
        retained = _id_list(facts["retained_release_ids"], label=f"{role}.retained_release_ids")
        terminal = _id_list(facts["terminal_candidate_ids"], label=f"{role}.terminal_candidate_ids")
        incoming = _id_list(facts["completed_incoming_ids"], label=f"{role}.completed_incoming_ids")
        if active == prior or retained != sorted([active, prior]) or terminal or incoming:
            raise ReleaseClosureError(f"{role} 未形成 active + exactly one prior 终态")
        result = {
            "retention_result": "pass",
            "retained_release_count": 2,
            "active_count": 1,
            "prior_count": 1,
            "terminal_candidates": 0,
            "completed_incoming": 0,
        }
    elif role == "runbook_drills_and_quality_report":
        facts = _closed(
            facts_value,
            {
                "documented_drills",
                "drill_checks_total",
                "drill_checks_passed",
                "quality_checks_total",
                "quality_checks_passed",
            },
            label=f"{role}.facts",
        )
        drills = _id_list(facts["documented_drills"], label=f"{role}.documented_drills")
        required = sorted(["bootstrap", "cleanup", "cutover", "local-prior", "rollback"])
        if drills != required:
            raise ReleaseClosureError(f"{role}.documented_drills 不完整")
        _complete_count_pair(
            facts, total="drill_checks_total", passed="drill_checks_passed", role=role
        )
        _complete_count_pair(
            facts,
            total="quality_checks_total",
            passed="quality_checks_passed",
            role=role,
        )
        result = {
            "runbook_result": "pass",
            "drill_result": "pass",
            "quality_report_result": "pass",
        }
    elif role == "revocation_surface":
        facts = _closed(
            facts_value,
            {
                "surfaces_scanned",
                "surface_checks_total",
                "surface_checks_passed",
                "periodic_state_copy_tasks",
                "outside_d_project_storage",
                "legacy_protection_exports",
            },
            label=f"{role}.facts",
        )
        surfaces = _id_list(facts["surfaces_scanned"], label=f"{role}.surfaces_scanned")
        required = sorted(
            [
                "cli",
                "config",
                "fresh-wheel",
                "runbook",
                "schema",
                "source",
                "vm-write-set",
                "windows-tasks",
            ]
        )
        if surfaces != required:
            raise ReleaseClosureError(f"{role}.surfaces_scanned 不完整")
        _complete_count_pair(
            facts,
            total="surface_checks_total",
            passed="surface_checks_passed",
            role=role,
        )
        for field in (
            "periodic_state_copy_tasks",
            "outside_d_project_storage",
            "legacy_protection_exports",
        ):
            if _count(facts[field], label=f"{role}.facts.{field}"):
                raise ReleaseClosureError(f"{role}.{field} 非零")
        result = {
            "revocation_surface_result": "pass",
            "periodic_state_copy_tasks": 0,
            "outside_d_project_storage": 0,
            "legacy_protection_exports": 0,
        }
    elif role == "identity_graph_negative_fixtures":
        facts = _closed(
            facts_value,
            {
                "positive_fixtures_total",
                "positive_fixtures_passed",
                "negative_fixtures_total",
                "negative_fixtures_rejected",
            },
            label=f"{role}.facts",
        )
        _complete_count_pair(
            facts,
            total="positive_fixtures_total",
            passed="positive_fixtures_passed",
            role=role,
        )
        _complete_count_pair(
            facts,
            total="negative_fixtures_total",
            passed="negative_fixtures_rejected",
            role=role,
        )
        result = {
            "schema_graph_hash_result": "pass",
            "negative_fixtures_rejected": True,
        }
    else:
        raise ReleaseClosureError("Stage 5 observation role 不受支持")
    return _expect_closed_assertions(result, _STAGE5_ASSERTIONS[role], role=role)


def _derive_stage6_assertions(role: str, facts_value: object) -> Mapping[str, object]:
    """从 GitHub/候选现场原始事实派生 Stage 6 断言。"""

    if role == "repository_private_observation":
        facts = _closed(
            facts_value,
            {"repository_visibility", "visibility_changed_at"},
            label=f"{role}.facts",
        )
        if facts["repository_visibility"] != "private":
            raise ReleaseClosureError("repository visibility 不是 private")
        _timestamp(facts["visibility_changed_at"], label="visibility_changed_at")
        result = dict(facts)
    elif role == "private_controls_revalidation":
        facts = _closed(
            facts_value,
            {
                "repository_visibility",
                "actual_plan_ok",
                "actions_ok",
                "branch_protection_ok",
                "environment_protection_ok",
                "publish_minimum_permissions_ok",
                "exact_sha_candidate_capability_ok",
            },
            label=f"{role}.facts",
        )
        if facts["repository_visibility"] != "private" or any(
            facts[field] is not True
            for field in facts
            if field.endswith("_ok")
        ):
            raise ReleaseClosureError(f"{role} controls 未全部通过")
        result = {
            "repository_visibility": "private",
            "actual_plan": "pass",
            "actions": "pass",
            "branch_protection": "pass",
            "environment_protection": "pass",
            "publish_minimum_permissions": "pass",
            "exact_sha_candidate_capability": "pass",
        }
    elif role == "private_exact_sha_ci":
        facts = _closed(
            facts_value,
            {"repository_visibility", "commit_sha", "ci_conclusion"},
            label=f"{role}.facts",
        )
        if facts["repository_visibility"] != "private" or facts["ci_conclusion"] != "success":
            raise ReleaseClosureError(f"{role} 未观察到 Private exact-SHA CI success")
        if not _is_commit(facts["commit_sha"]):
            raise ReleaseClosureError(f"{role}.commit_sha 无效")
        result = dict(facts)
    elif role == "private_candidate_only":
        facts = _closed(
            facts_value,
            {
                "repository_visibility",
                "mode",
                "production_switch_count",
                "candidate_checks_total",
                "candidate_checks_passed",
                "commit_sha",
                "candidate_release_id",
                "candidate_manifest_sha256",
            },
            label=f"{role}.facts",
        )
        if facts["repository_visibility"] != "private" or facts["mode"] != "candidate_only":
            raise ReleaseClosureError(f"{role} 不是 Private candidate_only")
        if _count(
            facts["production_switch_count"], label=f"{role}.production_switch_count"
        ):
            raise ReleaseClosureError(f"{role} 发生生产切换")
        _complete_count_pair(
            facts,
            total="candidate_checks_total",
            passed="candidate_checks_passed",
            role=role,
        )
        if not _is_commit(facts["commit_sha"]):
            raise ReleaseClosureError(f"{role}.commit_sha 无效")
        _identifier(facts["candidate_release_id"], label=f"{role}.candidate_release_id")
        _sha256(
            facts["candidate_manifest_sha256"], label=f"{role}.candidate_manifest_sha256"
        )
        result = {
            "repository_visibility": "private",
            "mode": "candidate_only",
            "production_switch": "not_performed",
            "candidate_result": "pass",
            "commit_sha": facts["commit_sha"],
            "candidate_release_id": facts["candidate_release_id"],
            "candidate_manifest_sha256": facts["candidate_manifest_sha256"],
        }
    elif role == "production_identity_unchanged":
        facts = _closed(
            facts_value,
            {
                "repository_visibility",
                "active_pointer_before_sha256",
                "active_pointer_after_sha256",
                "binding_before_sha256",
                "binding_after_sha256",
                "state_before_sha256",
                "state_after_sha256",
            },
            label=f"{role}.facts",
        )
        if facts["repository_visibility"] != "private":
            raise ReleaseClosureError(f"{role} 不是 Private observation")
        for prefix in ("active_pointer", "binding", "state"):
            _same_sha_pair(
                facts,
                before=f"{prefix}_before_sha256",
                after=f"{prefix}_after_sha256",
                role=role,
            )
        result = dict(facts)
    else:
        raise ReleaseClosureError("Stage 6 observation role 不受支持")
    return _expect_closed_assertions(result, _STAGE6_ASSERTIONS[role], role=role)


def _derive_assertions(
    role: str,
    facts: object,
    *,
    expected_roles: Sequence[str],
    independent: bool,
    mcp_acceptance: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    if role not in expected_roles:
        raise ReleaseClosureError("observation role 不属于当前阶段")
    if role in STAGE5_GATE_ROLES:
        return _derive_stage5_assertions(
            role,
            facts,
            independent=independent,
            mcp_acceptance=mcp_acceptance,
        )
    return _derive_stage6_assertions(role, facts)


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


def _campaign_inventory(root: Path, campaign_root: Path) -> tuple[Mapping[str, object], ...]:
    rows: list[Mapping[str, object]] = []
    total_bytes = 0
    try:
        entries = sorted(campaign_root.rglob("*"), key=lambda item: item.as_posix())
    except OSError as error:
        raise ReleaseClosureError("MCP acceptance evidence 无法枚举") from error
    if not entries or len(entries) > 4096:
        raise ReleaseClosureError("MCP acceptance evidence inventory 数量越界")
    for entry in entries:
        try:
            metadata = entry.lstat()
            relative = entry.relative_to(root).as_posix()
        except (OSError, ValueError) as error:
            raise ReleaseClosureError("MCP acceptance evidence inventory 逃逸") from error
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_flag:
            raise ReleaseClosureError("MCP acceptance evidence 含 symlink/reparse")
        if stat.S_ISDIR(metadata.st_mode):
            rows.append({"kind": "directory", "relative_path": relative})
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ReleaseClosureError("MCP acceptance evidence 含非 ordinary file")
        raw, _ = _stable_file_bytes(
            entry, maximum_bytes=_MAX_MCP_CAMPAIGN_FILE_BYTES
        )
        total_bytes += len(raw)
        if total_bytes > _MAX_MCP_CAMPAIGN_TOTAL_BYTES:
            raise ReleaseClosureError("MCP acceptance evidence 总大小越界")
        rows.append(
            {
                "kind": "file",
                "relative_path": relative,
                "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return tuple(rows)


def _validate_real_mcp_acceptance_evidence_root(
    evidence_root: Path, campaign_relative: str
) -> Mapping[str, object]:
    root = _evidence_root(evidence_root)
    relative = _relative_path(campaign_relative, label="MCP acceptance evidence root")
    campaign_root = _ordinary_directory(root, relative)
    before = _campaign_inventory(root, campaign_root)
    try:
        from quant_hub.knowledge_mcp.acceptance_cli import (
            validate_real_acceptance_evidence_root,
        )

        report_value = validate_real_acceptance_evidence_root(campaign_root)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise ReleaseClosureError("MCP real acceptance replay 未通过") from error
    after = _campaign_inventory(root, campaign_root)
    if canonical_bytes(list(before)) != canonical_bytes(list(after)):
        raise ReleaseClosureError("MCP acceptance evidence 在 replay 期间漂移")
    report = _closed(
        report_value,
        {
            "schema_version",
            "status",
            "authority",
            "run_id",
            "case_count",
            "preregistration_sha256",
            "campaign_receipt",
            "campaign_receipt_sha256",
        },
        label="MCP acceptance verification",
    )
    if (
        report["schema_version"] != "qrh-mcp-real-acceptance-verification/v1"
        or report["status"] != "PASS"
        or report["authority"] != _REAL_MCP_ACCEPTANCE_AUTHORITY
    ):
        raise ReleaseClosureError("MCP acceptance 不是 authoritative real-Codex PASS")
    _identifier(report["run_id"], label="MCP acceptance run_id")
    _positive_int(report["case_count"], label="MCP acceptance case_count")
    _sha256(report["preregistration_sha256"], label="MCP preregistration sha256")
    receipt_hash = _sha256(
        report["campaign_receipt_sha256"], label="MCP campaign receipt sha256"
    )
    receipt_relative = f"{relative}/campaign-receipt.json"
    receipt_path = _regular_file(root, receipt_relative)
    try:
        reported_receipt = Path(str(report["campaign_receipt"])).resolve(strict=True)
    except OSError as error:
        raise ReleaseClosureError("MCP campaign receipt path 无法解析") from error
    if reported_receipt != receipt_path:
        raise ReleaseClosureError("MCP campaign receipt path 与受管根不一致")
    raw, _ = _stable_file_bytes(receipt_path, maximum_bytes=_MAX_JSON_BYTES)
    if hashlib.sha256(raw).hexdigest() != receipt_hash:
        raise ReleaseClosureError("MCP campaign receipt hash 与 replay 不一致")
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseClosureError("MCP campaign receipt 无法解析") from error
    if (
        type(receipt) is not dict
        or receipt.get("schema_version") != _REAL_MCP_CAMPAIGN_SCHEMA
        or canonical_bytes(receipt) != raw
    ):
        raise ReleaseClosureError("MCP campaign receipt schema/canonical bytes 不一致")
    return report


def _managed_records(
    value: object, fields: set[str], *, label: str
) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or not value or len(value) > 100_000:
        raise ReleaseClosureError(f"{label} 必须是非空、有限 record list")
    records = [_closed(item, fields, label=f"{label} record") for item in value]
    identifiers = [_identifier(item["id"], label=f"{label}.id") for item in records]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise ReleaseClosureError(f"{label} 必须按 id 排序且唯一")
    return records


def _outcome_counts(records: Sequence[Mapping[str, object]], *, label: str) -> tuple[int, int]:
    passed = 0
    for record in records:
        outcome = record["outcome"]
        if outcome not in {"pass", "fail"}:
            raise ReleaseClosureError(f"{label}.outcome 不受支持")
        passed += int(outcome == "pass")
    return len(records), passed


def _artifact_ids(value: object, *, label: str, allow_empty: bool = False) -> list[str]:
    identifiers = _id_list(value, label=label)
    if not identifiers and not allow_empty:
        raise ReleaseClosureError(f"{label} 不得为空")
    return identifiers


def _artifact_hash(
    artifact_id: object,
    artifacts: Mapping[str, Mapping[str, object]],
    *,
    label: str,
) -> str:
    identifier = _identifier(artifact_id, label=label)
    try:
        return str(artifacts[identifier]["sha256"])
    except KeyError as error:
        raise ReleaseClosureError(f"{label} 未绑定 actual input artifact") from error


def _artifact_hash_pair(
    payload: Mapping[str, object],
    artifacts: Mapping[str, Mapping[str, object]],
    *,
    before: str,
    after: str,
    label: str,
) -> tuple[str, str]:
    before_id = _identifier(payload[before], label=f"{label}.{before}")
    after_id = _identifier(payload[after], label=f"{label}.{after}")
    if before_id == after_id:
        raise ReleaseClosureError(f"{label} before/after 必须是两个独立 capture")
    return (
        _artifact_hash(before_id, artifacts, label=f"{label}.{before}"),
        _artifact_hash(after_id, artifacts, label=f"{label}.{after}"),
    )


def _nonqualifying_managed_facts_preview(
    role: str,
    payload_value: object,
    support_artifacts: Mapping[str, Mapping[str, object]],
) -> Mapping[str, object]:
    """未注册的 shape-parser 脚手架；绝不构成 qualifying authority。

    `_load_managed_result` 在抵达本函数前无条件按 `_REQUIRED_REAL_GATE_ADAPTERS`
    fail closed。未来只有真实 adapter 已重放底层 receipt/API/VM audit 后，才可删除
    该阻断并用 adapter 的返回值派生 assertions；不得直接接通本函数。
    """

    label = f"{role}.managed_result.payload"
    if role == "full_replay_and_comment_lifecycle":
        payload = _closed(
            payload_value,
            {
                "browser_checks",
                "sqlite_checks",
                "source_before_artifact_id",
                "source_after_artifact_id",
                "comment_attachments",
            },
            label=label,
        )
        browser = _managed_records(payload["browser_checks"], {"id", "outcome"}, label=f"{label}.browser_checks")
        sqlite = _managed_records(payload["sqlite_checks"], {"id", "outcome"}, label=f"{label}.sqlite_checks")
        attachments = _managed_records(
            payload["comment_attachments"],
            {"id", "expected_target", "actual_target"},
            label=f"{label}.comment_attachments",
        )
        browser_total, browser_passed = _outcome_counts(browser, label=label)
        sqlite_total, sqlite_passed = _outcome_counts(sqlite, label=label)
        source_before, source_after = _artifact_hash_pair(
            payload,
            support_artifacts,
            before="source_before_artifact_id",
            after="source_after_artifact_id",
            label=label,
        )
        wrong = 0
        for record in attachments:
            expected = _text(record["expected_target"], label=f"{label}.expected_target")
            actual = _text(record["actual_target"], label=f"{label}.actual_target")
            wrong += int(expected != actual)
        return {
            "browser_checks_total": browser_total,
            "browser_checks_passed": browser_passed,
            "sqlite_checks_total": sqlite_total,
            "sqlite_checks_passed": sqlite_passed,
            "source_bytes_before_sha256": source_before,
            "source_bytes_after_sha256": source_after,
            "wrong_comment_attachments": wrong,
        }
    if role == "failure_and_incremental_matrix":
        payload = _closed(payload_value, {"cases", "failure_events"}, label=label)
        cases = _managed_records(payload["cases"], {"id", "outcome"}, label=f"{label}.cases")
        events = _managed_records(
            payload["failure_events"], {"id", "detected"}, label=f"{label}.failure_events"
        )
        total, passed = _outcome_counts(cases, label=label)
        silent = 0
        for record in events:
            if type(record["detected"]) is not bool:
                raise ReleaseClosureError(f"{label}.failure_events.detected 必须是 bool")
            silent += int(not record["detected"])
        return {
            "matrix_cases_total": total,
            "matrix_cases_passed": passed,
            "silent_failures": silent,
        }
    if role == "web_search_mcp_snapshot_consistency":
        payload = _closed(
            payload_value,
            {"checks", "responses", "mcp_acceptance_evidence_root"},
            label=label,
        )
        checks = _managed_records(payload["checks"], {"id", "outcome"}, label=f"{label}.checks")
        responses = _managed_records(
            payload["responses"],
            {"id", "requested_snapshot_id", "returned_snapshot_id"},
            label=f"{label}.responses",
        )
        total, passed = _outcome_counts(checks, label=label)
        stale = 0
        for record in responses:
            requested = _identifier(record["requested_snapshot_id"], label=f"{label}.requested")
            returned = _identifier(record["returned_snapshot_id"], label=f"{label}.returned")
            stale += int(requested != returned)
        return {
            "snapshot_checks_total": total,
            "snapshot_checks_passed": passed,
            "stale_current_returns": stale,
            "mcp_acceptance_evidence_root": _relative_path(
                payload["mcp_acceptance_evidence_root"], label=f"{label}.mcp_root"
            ),
        }
    if role == "independent_verification":
        payload = _closed(
            payload_value,
            {"inspected_artifact_ids", "findings", "executor_summary_artifact_ids"},
            label=label,
        )
        inspected = _artifact_ids(payload["inspected_artifact_ids"], label=f"{label}.inspected")
        if inspected != sorted(support_artifacts):
            raise ReleaseClosureError("independent verifier input closure 与托管 artifacts 不一致")
        findings = _managed_records(
            payload["findings"], {"id", "severity"}, label=f"{label}.findings"
        ) if payload["findings"] else []
        severity_counts = {"p0": 0, "p1": 0, "p2": 0}
        for finding in findings:
            severity = finding["severity"]
            if severity not in severity_counts:
                raise ReleaseClosureError(f"{label}.finding severity 不受支持")
            severity_counts[str(severity)] += 1
        summaries = _artifact_ids(
            payload["executor_summary_artifact_ids"],
            label=f"{label}.executor_summary",
            allow_empty=True,
        )
        for artifact_id in summaries:
            _artifact_hash(artifact_id, support_artifacts, label=f"{label}.executor_summary")
        return {
            "inspected_artifacts": len(inspected),
            "p0_findings": severity_counts["p0"],
            "p1_findings": severity_counts["p1"],
            "p2_findings": severity_counts["p2"],
            "executor_summary_inputs": len(summaries),
        }
    if role == "shared_state_schema_compatibility":
        payload = _closed(
            payload_value,
            {"checks", "state_before_artifact_id", "state_after_artifact_id", "migration_events"},
            label=label,
        )
        checks = _managed_records(
            payload["checks"], {"id", "release_role", "outcome"}, label=f"{label}.checks"
        )
        candidate = [record for record in checks if record["release_role"] == "candidate"]
        prior = [record for record in checks if record["release_role"] == "prior"]
        if len(candidate) + len(prior) != len(checks) or not candidate or not prior:
            raise ReleaseClosureError(f"{label}.release_role 不闭合")
        candidate_total, candidate_passed = _outcome_counts(candidate, label=label)
        prior_total, prior_passed = _outcome_counts(prior, label=label)
        state_before, state_after = _artifact_hash_pair(
            payload,
            support_artifacts,
            before="state_before_artifact_id",
            after="state_after_artifact_id",
            label=label,
        )
        events = _managed_records(
            payload["migration_events"], {"id", "kind"}, label=f"{label}.migration_events"
        ) if payload["migration_events"] else []
        down = sum(record["kind"] == "down_migration" for record in events)
        return {
            "candidate_checks_total": candidate_total,
            "candidate_checks_passed": candidate_passed,
            "prior_checks_total": prior_total,
            "prior_checks_passed": prior_passed,
            "state_before_sha256": state_before,
            "state_after_sha256": state_after,
            "down_migration_count": down,
        }
    if role == "active_prior_active_drill":
        payload = _closed(
            payload_value,
            {
                "transition_sequence",
                "transition_checks",
                "state_before_artifact_id",
                "state_after_artifact_id",
                "process_events",
                "file_reads",
            },
            label=label,
        )
        transition = _managed_records(
            payload["transition_checks"], {"id", "outcome"}, label=f"{label}.checks"
        )
        total, passed = _outcome_counts(transition, label=label)
        state_before, state_after = _artifact_hash_pair(
            payload,
            support_artifacts,
            before="state_before_artifact_id",
            after="state_after_artifact_id",
            label=label,
        )
        processes = _managed_records(
            payload["process_events"], {"id", "action", "project_root"}, label=f"{label}.process_events"
        ) if payload["process_events"] else []
        c_restarts = 0
        for event in processes:
            root = PureWindowsPath(_text(event["project_root"], label=f"{label}.project_root"))
            c_restarts += int(event["action"] == "restart" and root.drive.casefold() == "c:")
        reads = _managed_records(payload["file_reads"], {"id", "path"}, label=f"{label}.file_reads")
        exact_root = PureWindowsPath(EXACT_VM_PROJECT_ROOT)
        outside = 0
        for event in reads:
            path = PureWindowsPath(_text(event["path"], label=f"{label}.file_read.path"))
            try:
                path.relative_to(exact_root)
            except ValueError:
                outside += 1
        return {
            "transition_sequence": payload["transition_sequence"],
            "transition_checks_total": total,
            "transition_checks_passed": passed,
            "state_before_sha256": state_before,
            "state_after_sha256": state_after,
            "legacy_c_writer_restart_count": c_restarts,
            "outside_exact_d_project_reads": outside,
        }
    if role == "retention_closure":
        payload = _closed(
            payload_value,
            {"retained_release_ids", "terminal_candidate_ids", "completed_incoming_ids"},
            label=label,
        )
        return {
            "active_release_id": _SUBJECT_SENTINEL,
            "prior_release_id": _SUBJECT_SENTINEL,
            "retained_release_ids": _id_list(payload["retained_release_ids"], label=f"{label}.retained"),
            "terminal_candidate_ids": _id_list(payload["terminal_candidate_ids"], label=f"{label}.candidate"),
            "completed_incoming_ids": _id_list(payload["completed_incoming_ids"], label=f"{label}.incoming"),
        }
    if role == "runbook_drills_and_quality_report":
        payload = _closed(payload_value, {"drills", "quality_checks"}, label=label)
        drills = _managed_records(payload["drills"], {"id", "outcome"}, label=f"{label}.drills")
        quality = _managed_records(
            payload["quality_checks"], {"id", "outcome"}, label=f"{label}.quality"
        )
        drill_total, drill_passed = _outcome_counts(drills, label=label)
        quality_total, quality_passed = _outcome_counts(quality, label=label)
        return {
            "documented_drills": [str(item["id"]) for item in drills],
            "drill_checks_total": drill_total,
            "drill_checks_passed": drill_passed,
            "quality_checks_total": quality_total,
            "quality_checks_passed": quality_passed,
        }
    if role == "revocation_surface":
        payload = _closed(payload_value, {"scans"}, label=label)
        scans = _managed_records(
            payload["scans"], {"id", "outcome", "findings"}, label=f"{label}.scans"
        )
        total, passed = _outcome_counts(scans, label=label)
        counts = {
            "periodic_state_copy_task": 0,
            "outside_d_project_storage": 0,
            "legacy_protection_export": 0,
        }
        for scan in scans:
            findings = scan["findings"]
            if not isinstance(findings, list):
                raise ReleaseClosureError(f"{label}.scan.findings 必须是 list")
            for finding in findings:
                typed = _closed(finding, {"category", "location"}, label=f"{label}.finding")
                category = typed["category"]
                if category not in counts:
                    raise ReleaseClosureError(f"{label}.finding category 不受支持")
                _text(typed["location"], label=f"{label}.finding.location", maximum=1024)
                counts[str(category)] += 1
        return {
            "surfaces_scanned": [str(item["id"]) for item in scans],
            "surface_checks_total": total,
            "surface_checks_passed": passed,
            "periodic_state_copy_tasks": counts["periodic_state_copy_task"],
            "outside_d_project_storage": counts["outside_d_project_storage"],
            "legacy_protection_exports": counts["legacy_protection_export"],
        }
    if role == "identity_graph_negative_fixtures":
        payload = _closed(payload_value, {"fixtures"}, label=label)
        fixtures = _managed_records(
            payload["fixtures"], {"id", "expected", "actual"}, label=f"{label}.fixtures"
        )
        positive = [item for item in fixtures if item["expected"] == "accept"]
        negative = [item for item in fixtures if item["expected"] == "reject"]
        if len(positive) + len(negative) != len(fixtures) or not positive or not negative:
            raise ReleaseClosureError(f"{label}.expected 不闭合")
        return {
            "positive_fixtures_total": len(positive),
            "positive_fixtures_passed": sum(item["actual"] == "accept" for item in positive),
            "negative_fixtures_total": len(negative),
            "negative_fixtures_rejected": sum(item["actual"] == "reject" for item in negative),
        }
    if role == "repository_private_observation":
        payload = _closed(payload_value, {"repository"}, label=label)
        repository = _closed(payload["repository"], {"visibility", "visibility_changed_at"}, label=f"{label}.repository")
        return {
            "repository_visibility": repository["visibility"],
            "visibility_changed_at": repository["visibility_changed_at"],
        }
    if role == "private_controls_revalidation":
        payload = _closed(payload_value, {"repository_visibility", "checks"}, label=label)
        checks = _managed_records(payload["checks"], {"id", "outcome"}, label=f"{label}.checks")
        outcomes = {str(item["id"]): item["outcome"] for item in checks}
        required = {
            "actual-plan",
            "actions",
            "branch-protection",
            "environment-protection",
            "exact-sha-candidate-capability",
            "publish-minimum-permissions",
        }
        if set(outcomes) != required:
            raise ReleaseClosureError(f"{label}.checks 不完整")
        return {
            "repository_visibility": payload["repository_visibility"],
            "actual_plan_ok": outcomes["actual-plan"] == "pass",
            "actions_ok": outcomes["actions"] == "pass",
            "branch_protection_ok": outcomes["branch-protection"] == "pass",
            "environment_protection_ok": outcomes["environment-protection"] == "pass",
            "publish_minimum_permissions_ok": outcomes["publish-minimum-permissions"] == "pass",
            "exact_sha_candidate_capability_ok": outcomes["exact-sha-candidate-capability"] == "pass",
        }
    if role == "private_exact_sha_ci":
        payload = _closed(payload_value, {"repository_visibility", "check_run"}, label=label)
        check = _closed(payload["check_run"], {"head_sha", "conclusion"}, label=f"{label}.check_run")
        return {
            "repository_visibility": payload["repository_visibility"],
            "commit_sha": check["head_sha"],
            "ci_conclusion": check["conclusion"],
        }
    if role == "private_candidate_only":
        payload = _closed(
            payload_value,
            {"repository_visibility", "mode", "production_switch_events", "checks", "commit_sha", "candidate_release_id", "candidate_manifest_sha256"},
            label=label,
        )
        checks = _managed_records(payload["checks"], {"id", "outcome"}, label=f"{label}.checks")
        total, passed = _outcome_counts(checks, label=label)
        switches = payload["production_switch_events"]
        if not isinstance(switches, list):
            raise ReleaseClosureError(f"{label}.production_switch_events 必须是 list")
        return {
            "repository_visibility": payload["repository_visibility"],
            "mode": payload["mode"],
            "production_switch_count": len(switches),
            "candidate_checks_total": total,
            "candidate_checks_passed": passed,
            "commit_sha": payload["commit_sha"],
            "candidate_release_id": payload["candidate_release_id"],
            "candidate_manifest_sha256": payload["candidate_manifest_sha256"],
        }
    if role == "production_identity_unchanged":
        payload = _closed(
            payload_value,
            {
                "repository_visibility",
                "active_pointer_before_artifact_id",
                "active_pointer_after_artifact_id",
                "binding_before_artifact_id",
                "binding_after_artifact_id",
                "state_before_artifact_id",
                "state_after_artifact_id",
            },
            label=label,
        )
        facts: dict[str, object] = {"repository_visibility": payload["repository_visibility"]}
        for prefix in ("active_pointer", "binding", "state"):
            before_hash, after_hash = _artifact_hash_pair(
                payload,
                support_artifacts,
                before=f"{prefix}_before_artifact_id",
                after=f"{prefix}_after_artifact_id",
                label=label,
            )
            facts[f"{prefix}_before_sha256"] = before_hash
            facts[f"{prefix}_after_sha256"] = after_hash
        return facts
    raise ReleaseClosureError("managed result role 不受支持")


_SUBJECT_SENTINEL = "__derived_from_subject__"


def _subject_from_artifacts(
    root: Path, refs: Sequence[Mapping[str, object]]
) -> Mapping[str, object]:
    documents: list[tuple[Mapping[str, object], Mapping[str, object]]] = []
    for ref in refs:
        if ref["artifact_kind"] != "canonical_json":
            raise ReleaseClosureError("subject artifact 必须是 canonical JSON")
        document, _ = _canonical_json_file(root, str(ref["relative_path"]))
        documents.append((ref, document))
    active_docs = [item for item in documents if item[0]["schema_version"] == ACTIVE_RELEASE_SCHEMA]
    binding_docs = [item for item in documents if item[0]["schema_version"] == LOCAL_PRIOR_BINDING_SCHEMA]
    manifests = [item for item in documents if item[0]["schema_version"] == RELEASE_MANIFEST_SCHEMA]
    if len(active_docs) != 1 or len(binding_docs) != 1 or len(manifests) != 2 or len(documents) != 4:
        raise ReleaseClosureError("subject closure 必须恰含 active、binding 与两个 manifest")
    try:
        active = validate_active_release(active_docs[0][1])
        binding = validate_local_prior_binding(binding_docs[0][1])
        manifest_values = [validate_release_manifest(item[1]) for item in manifests]
    except LocalReleaseIdentityError as error:
        raise ReleaseClosureError("subject local release identity 无效") from error
    if canonical_bytes(active["release"]) != canonical_bytes(binding["active"]):
        raise ReleaseClosureError("active pointer 与 prior binding 漂移")
    manifest_by_hash = {identity_sha256(item): item for item in manifest_values}
    active_ref = binding["active"]
    prior_ref = binding["prior"]
    assert isinstance(active_ref, Mapping) and isinstance(prior_ref, Mapping)
    if set(manifest_by_hash) != {active_ref["manifest_sha256"], prior_ref["manifest_sha256"]}:
        raise ReleaseClosureError("subject manifests 与 active/prior binding 不闭合")
    active_manifest = manifest_by_hash[str(active_ref["manifest_sha256"])]
    prior_manifest = manifest_by_hash[str(prior_ref["manifest_sha256"])]
    subject = {
        "active_release": {
            "release_id": active_ref["release_id"],
            "manifest_sha256": active_ref["manifest_sha256"],
            "snapshot_id": active_manifest["content"]["snapshot_id"],
        },
        "prior_release": {
            "release_id": prior_ref["release_id"],
            "manifest_sha256": prior_ref["manifest_sha256"],
            "snapshot_id": prior_manifest["content"]["snapshot_id"],
        },
        "state_identity_sha256": binding["state_identity"]["identity_sha256"],
    }
    return _validate_subject(subject)


def _load_identity_graph_fixture_report(
    root: Path,
    *,
    result_ref: Mapping[str, object],
    input_refs: Sequence[Mapping[str, object]],
    support_artifacts: Mapping[str, Mapping[str, object]],
) -> tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object], str]:
    """现场重放固定 corpus；report 中的 expected/observed 字符串不作权威输入。"""

    if len(support_artifacts) != 1:
        raise ReleaseClosureError(
            "identity graph report support closure 必须恰含固定 corpus"
        )
    corpus_ref = next(iter(support_artifacts.values()))
    if (
        corpus_ref["artifact_kind"] != "canonical_json"
        or corpus_ref["schema_version"] != IDENTITY_GRAPH_CORPUS_SCHEMA
    ):
        raise ReleaseClosureError("identity graph corpus artifact schema 不受支持")
    corpus, corpus_raw = _canonical_json_file(
        root, str(corpus_ref["relative_path"])
    )
    expected_corpus = fixed_corpus_document()
    if corpus_raw != canonical_bytes(expected_corpus):
        raise ReleaseClosureError("identity graph corpus bytes/hash 漂移")
    try:
        replayed = replay_fixed_corpus(corpus)
    except IdentityGraphFixtureError as error:
        raise ReleaseClosureError("identity graph fixture 现场重放失败") from error

    report, _ = _canonical_json_file(root, str(result_ref["relative_path"]))
    report = _closed(
        report,
        {
            "schema_version",
            "report_id",
            "gate_role",
            "authority_scope",
            "producer",
            "produced_at",
            "input_artifact_aggregate_sha256",
            "corpus",
            "fixtures",
            "result",
            "report_sha256",
        },
        label="identity graph fixture report",
    )
    if (
        report["schema_version"] != IDENTITY_GRAPH_REPORT_SCHEMA
        or report["gate_role"] != IDENTITY_GRAPH_GATE_ROLE
        or report["authority_scope"] != IDENTITY_GRAPH_REPORT_AUTHORITY_SCOPE
    ):
        raise ReleaseClosureError("identity graph report identity/scope 漂移")
    _identifier(report["report_id"], label="identity graph report_id")
    produced_at = _timestamp(
        report["produced_at"], label="identity graph report.produced_at"
    )
    producer_value = _closed(
        report["producer"], {"name", "version"}, label="identity graph producer"
    )
    if producer_value != {
        "name": IDENTITY_GRAPH_PRODUCER_NAME,
        "version": IDENTITY_GRAPH_PRODUCER_VERSION,
    }:
        raise ReleaseClosureError("identity graph producer identity 漂移")
    expected_input_aggregate = artifact_input_aggregate_sha256(input_refs)
    if report["input_artifact_aggregate_sha256"] != expected_input_aggregate:
        raise ReleaseClosureError("identity graph subject/support closure 漂移")
    corpus_value = _closed(
        report["corpus"],
        {"schema_version", "sha256", "size_bytes"},
        label="identity graph report corpus",
    )
    if corpus_value != {
        "schema_version": IDENTITY_GRAPH_CORPUS_SCHEMA,
        "sha256": hashlib.sha256(corpus_raw).hexdigest(),
        "size_bytes": len(corpus_raw),
    }:
        raise ReleaseClosureError("identity graph report corpus identity 漂移")
    if (
        corpus_ref["sha256"] != corpus_value["sha256"]
        or corpus_ref["size_bytes"] != corpus_value["size_bytes"]
    ):
        raise ReleaseClosureError("identity graph support ref 与 corpus 不一致")

    fixtures_value = report["fixtures"]
    if not isinstance(fixtures_value, list) or canonical_bytes(
        fixtures_value
    ) != canonical_bytes(list(replayed)):
        raise ReleaseClosureError(
            "identity graph report outcome 不是现场 linter 重放结果"
        )
    positive = [item for item in replayed if item["expected_result"] == "accept"]
    negative = [item for item in replayed if item["expected_result"] == "reject"]
    expected_result = {
        "positive_fixtures_total": len(positive),
        "positive_fixtures_accepted": len(positive),
        "negative_fixtures_total": len(negative),
        "negative_fixtures_rejected": len(negative),
    }
    result = _closed(
        report["result"], set(expected_result), label="identity graph report result"
    )
    if result != expected_result:
        raise ReleaseClosureError("identity graph report aggregate 不是现场重放结果")
    _self_hash(report, "report_sha256", label="identity graph fixture report")
    return (
        report,
        {
            "positive_fixtures_total": len(positive),
            "positive_fixtures_passed": len(positive),
            "negative_fixtures_total": len(negative),
            "negative_fixtures_rejected": len(negative),
        },
        {
            "name": IDENTITY_GRAPH_PRODUCER_NAME,
            "version": IDENTITY_GRAPH_PRODUCER_VERSION,
            "independent": False,
        },
        _utc_text(produced_at),
    )


def _load_managed_result(
    root: Path,
    role: str,
    result_ref: Mapping[str, object],
    input_refs: Sequence[Mapping[str, object]],
    support_artifacts: Mapping[str, Mapping[str, object]],
    subject: Mapping[str, object],
) -> tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object], str]:
    if (
        role == IDENTITY_GRAPH_GATE_ROLE
        and result_ref["artifact_kind"] == "canonical_json"
        and result_ref["schema_version"] == IDENTITY_GRAPH_REPORT_SCHEMA
    ):
        return _load_identity_graph_fixture_report(
            root,
            result_ref=result_ref,
            input_refs=input_refs,
            support_artifacts=support_artifacts,
        )
    expected_schema = _MANAGED_RESULT_SCHEMAS[role]
    if (
        result_ref["artifact_kind"] != "canonical_json"
        or result_ref["schema_version"] != expected_schema
    ):
        raise ReleaseClosureError("primary managed result schema 不受支持")
    result, _ = _canonical_json_file(root, str(result_ref["relative_path"]))
    result = _closed(
        result,
        {"schema_version", "result_id", "gate_role", "authority", "observer", "execution", "payload", "result_sha256"},
        label="managed observer result",
    )
    if result["schema_version"] != expected_schema or result["gate_role"] != role:
        raise ReleaseClosureError("managed result role/schema 漂移")
    _identifier(result["result_id"], label="managed result_id")
    expected_authority = _MANAGED_AUTHORITIES[role]
    if result["authority"] != expected_authority:
        raise ReleaseClosureError("managed result producer authority 不在 allow-list")
    observer = _closed(result["observer"], {"name", "version"}, label="managed result observer")
    expected_name = _MANAGED_OBSERVER_NAMES[expected_authority]
    if observer["name"] != expected_name:
        raise ReleaseClosureError("managed result observer name 不在 allow-list")
    _text(observer["version"], label="managed result observer.version", maximum=180)
    execution = _closed(
        result["execution"],
        {
            "dispatch_id",
            "command",
            "cwd",
            "executable_sha256",
            "input_artifact_aggregate_sha256",
            "payload_sha256",
            "output_relative_path",
            "started_at",
            "finished_at",
            "exit_code",
        },
        label="managed result execution",
    )
    _identifier(execution["dispatch_id"], label="managed dispatch_id")
    if execution["command"] != [expected_name, role]:
        raise ReleaseClosureError("managed execution command 不在 allow-list")
    if execution["cwd"] != EXACT_VM_PROJECT_ROOT:
        raise ReleaseClosureError("managed execution cwd 不是 exact D project root")
    _sha256(execution["executable_sha256"], label="managed executable_sha256")
    expected_inputs = hashlib.sha256(canonical_bytes(list(input_refs))).hexdigest()
    if execution["input_artifact_aggregate_sha256"] != expected_inputs:
        raise ReleaseClosureError("managed execution input closure 漂移")
    expected_payload = hashlib.sha256(canonical_bytes(result["payload"])).hexdigest()
    if execution["payload_sha256"] != expected_payload:
        raise ReleaseClosureError("managed execution payload hash 漂移")
    if execution["output_relative_path"] != result_ref["relative_path"]:
        raise ReleaseClosureError("managed execution output path 漂移")
    started = _timestamp(execution["started_at"], label="managed execution.started_at")
    finished = _timestamp(execution["finished_at"], label="managed execution.finished_at")
    if finished < started or execution["exit_code"] != 0:
        raise ReleaseClosureError("managed execution 未成功闭合")
    _self_hash(result, "result_sha256", label="managed observer result")
    required_schema, adapter = _REQUIRED_REAL_GATE_ADAPTERS[role]
    raise ReleaseClosureError(
        f"{role} non-qualifying：缺少 {required_schema} 的真实 {adapter}；"
        "managed wrapper/self-hash/exit_code 不赋予 PASS authority"
    )


def _load_gate_observation(
    root: Path, relative_path: str, *, expected_roles: Sequence[str]
) -> tuple[
    Mapping[str, object],
    Mapping[str, object],
    Mapping[str, object],
    tuple[Mapping[str, object], ...],
]:
    """从受管 result、actual subject pointers/manifests 与底层输入派生 gate。"""

    relative = _relative_path(relative_path, label="observation relative path")
    observation, raw = _canonical_json_file(root, relative)
    observation = _closed(
        observation,
        {
            "schema_version",
            "observation_id",
            "gate_role",
            "sealed_at",
            "result_artifact",
            "subject_artifacts",
            "support_artifacts",
            "observation_sha256",
        },
        label="closure gate observation",
    )
    if observation["schema_version"] != GATE_OBSERVATION_SCHEMA:
        raise ReleaseClosureError("gate observation schema_version 不受支持")
    observation_id = _identifier(observation["observation_id"], label="observation_id")
    role = _identifier(observation["gate_role"], label="observation.gate_role")
    if role not in expected_roles:
        raise ReleaseClosureError("observation role 不属于当前阶段")
    sealed_at = _timestamp(observation["sealed_at"], label="observation.sealed_at")
    result_value = observation["result_artifact"]
    subject_values = observation["subject_artifacts"]
    support_values = observation["support_artifacts"]
    if not isinstance(subject_values, list) or not isinstance(support_values, list):
        raise ReleaseClosureError("observation artifact groups 必须是 list")
    if len(subject_values) != 4 or not support_values:
        raise ReleaseClosureError("observation 缺少 exact subject/support input closure")
    if 1 + len(subject_values) + len(support_values) > _MAX_ARTIFACTS - 1:
        raise ReleaseClosureError("observation artifact 数量越界")
    artifact_values = [result_value, *subject_values, *support_values]
    validated = tuple(
        _validate_artifact_ref(
            item,
            root=root,
            evidence_relative_path=relative,
            evidence_observed_at=sealed_at,
        )
        for item in artifact_values
    )
    keys = [(item["artifact_id"], item["relative_path"]) for item in validated]
    if len(keys) != len(set(keys)):
        raise ReleaseClosureError("observation artifact list 必须唯一")
    if any(item["artifact_id"] == observation_id for item in validated):
        raise ReleaseClosureError("observation_id 与 source artifact_id 冲突")
    validated_by_key = {
        (str(item["artifact_id"]), str(item["relative_path"])): item
        for item in validated
    }
    result_key = (str(result_value.get("artifact_id")), str(result_value.get("relative_path"))) if isinstance(result_value, Mapping) else ("", "")
    try:
        result_ref = validated_by_key[result_key]
    except KeyError as error:
        raise ReleaseClosureError("managed result artifact ref 未闭合") from error
    subject_keys = {
        (str(item.get("artifact_id")), str(item.get("relative_path")))
        for item in subject_values
        if isinstance(item, Mapping)
    }
    support_keys = {
        (str(item.get("artifact_id")), str(item.get("relative_path")))
        for item in support_values
        if isinstance(item, Mapping)
    }
    if len(subject_keys) != 4 or len(support_keys) != len(support_values):
        raise ReleaseClosureError("observation artifact groups 含重复或无效 ref")
    for values, label in (
        (subject_values, "subject_artifacts"),
        (support_values, "support_artifacts"),
    ):
        group_keys = [
            (str(item["artifact_id"]), str(item["relative_path"]))
            for item in values
            if isinstance(item, Mapping)
        ]
        if group_keys != sorted(group_keys):
            raise ReleaseClosureError(f"observation {label} 必须按 identity/path 排序")
    subject_refs = tuple(validated_by_key[key] for key in sorted(subject_keys))
    support_refs = tuple(validated_by_key[key] for key in sorted(support_keys))
    input_refs = tuple(
        sorted(
            [*subject_refs, *support_refs],
            key=lambda item: (str(item["artifact_id"]), str(item["relative_path"])),
        )
    )
    subject = _subject_from_artifacts(root, subject_refs)
    support_by_id = {str(item["artifact_id"]): item for item in support_refs}
    if len(support_by_id) != len(support_refs):
        raise ReleaseClosureError("support artifact_id 必须唯一")
    _, facts, producer, finished_at = _load_managed_result(
        root,
        role,
        result_ref,
        input_refs,
        support_by_id,
        subject,
    )
    if _timestamp(finished_at, label="managed result finished_at") > sealed_at:
        raise ReleaseClosureError("observation 早于 managed execution 完成")
    if role == "retention_closure":
        facts = dict(facts)
        facts["active_release_id"] = subject["active_release"]["release_id"]
        facts["prior_release_id"] = subject["prior_release"]["release_id"]
    mcp_acceptance: Mapping[str, object] | None = None
    if role == "web_search_mcp_snapshot_consistency":
        mcp_acceptance = _validate_real_mcp_acceptance_evidence_root(
            root,
            str(facts["mcp_acceptance_evidence_root"]),
        )
    assertions = _derive_assertions(
        role,
        facts,
        expected_roles=expected_roles,
        independent=bool(producer["independent"]),
        mcp_acceptance=mcp_acceptance,
    )
    if mcp_acceptance is not None:
        campaign_relative = _relative_path(
            facts["mcp_acceptance_evidence_root"],
            label="MCP acceptance evidence root",
        )
        receipt_relative = f"{campaign_relative}/campaign-receipt.json"
        receipt_refs = [
            item
            for item in support_refs
            if item["relative_path"] == receipt_relative
            and item["artifact_kind"] == "canonical_json"
            and item["schema_version"] == _REAL_MCP_CAMPAIGN_SCHEMA
        ]
        if (
            len(receipt_refs) != 1
            or receipt_refs[0]["sha256"]
            != mcp_acceptance["campaign_receipt_sha256"]
        ):
            raise ReleaseClosureError("typed observation 未托管 exact MCP campaign receipt")
    _self_hash(observation, "observation_sha256", label="gate observation")
    observation_ref = {
        "artifact_id": observation_id,
        "relative_path": relative,
        "artifact_kind": "canonical_json",
        "schema_version": GATE_OBSERVATION_SCHEMA,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "observed_at": observation["sealed_at"],
    }
    derived_observation = {
        "schema_version": observation["schema_version"],
        "observation_id": observation_id,
        "gate_role": role,
        "subject": subject,
        "observed_at": observation["sealed_at"],
        "observer": producer,
        "observation_sha256": observation["observation_sha256"],
    }
    return derived_observation, assertions, observation_ref, validated


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
    observation_refs = [
        item
        for item in validated
        if item["artifact_kind"] == "canonical_json"
        and item["schema_version"] == GATE_OBSERVATION_SCHEMA
    ]
    if len(observation_refs) != 1:
        raise ReleaseClosureError("gate evidence 必须恰好绑定一个 typed observation")
    observation, derived, observation_ref, sources = _load_gate_observation(
        root,
        str(observation_refs[0]["relative_path"]),
        expected_roles=expected_roles,
    )
    expected_artifacts = sorted(
        [observation_ref, *sources],
        key=lambda item: (str(item["artifact_id"]), str(item["relative_path"])),
    )
    if canonical_bytes(list(validated)) != canonical_bytes(expected_artifacts):
        raise ReleaseClosureError("gate artifact custody 与 typed observation 不一致")
    if canonical_bytes(observation_refs[0]) != canonical_bytes(observation_ref):
        raise ReleaseClosureError("typed observation file closure 漂移")
    expected_fields = {
        "gate_role": observation["gate_role"],
        "subject": observation["subject"],
        "assertions": derived,
        "observed_at": observation["observed_at"],
        "producer": observation["observer"],
    }
    for field, expected in expected_fields.items():
        if canonical_bytes(evidence[field]) != canonical_bytes(expected):
            raise ReleaseClosureError(f"gate {field} 不是由 typed observation 派生")
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


def produce_gate_evidence_from_observation(
    evidence_root: Path, observation_path: str
) -> Mapping[str, object]:
    """把一个受管 typed observation 收敛为可供 certificate 消费的 gate evidence。"""

    root = _evidence_root(evidence_root)
    relative = _relative_path(observation_path, label="observation path")
    first = _load_gate_observation(
        root,
        relative,
        expected_roles=(*STAGE5_GATE_ROLES, *STAGE6_GATE_ROLES),
    )
    second = _load_gate_observation(
        root,
        relative,
        expected_roles=(*STAGE5_GATE_ROLES, *STAGE6_GATE_ROLES),
    )
    first_material = [first[0], first[1], first[2], list(first[3])]
    second_material = [second[0], second[1], second[2], list(second[3])]
    if canonical_bytes(first_material) != canonical_bytes(second_material):
        raise ReleaseClosureError("gate observation closure 在派生期间漂移")
    observation, assertions, observation_ref, sources = first
    role = str(observation["gate_role"])
    artifacts = sorted(
        [observation_ref, *sources],
        key=lambda item: (str(item["artifact_id"]), str(item["relative_path"])),
    )
    evidence_id_material = {
        "observation_sha256": observation["observation_sha256"],
        "gate_role": role,
        "subject": observation["subject"],
    }
    evidence: dict[str, object] = {
        "schema_version": GATE_EVIDENCE_SCHEMA,
        "evidence_id": "gate-"
        + hashlib.sha256(canonical_bytes(evidence_id_material)).hexdigest()[:32],
        "gate_role": role,
        "subject": observation["subject"],
        "verdict": "pass",
        "assertions": assertions,
        "observed_at": observation["observed_at"],
        "producer": observation["observer"],
        "artifacts": artifacts,
    }
    evidence["evidence_sha256"] = hashlib.sha256(canonical_bytes(evidence)).hexdigest()
    expected_roles = STAGE5_GATE_ROLES if role in STAGE5_GATE_ROLES else STAGE6_GATE_ROLES
    return _validate_gate_evidence(
        evidence,
        root=root,
        relative_path="derived-gate-evidence.json",
        expected_roles=expected_roles,
    )


def write_gate_evidence_from_observation(
    evidence_root: Path, observation_path: str, *, output_path: str
) -> Mapping[str, object]:
    evidence = produce_gate_evidence_from_observation(evidence_root, observation_path)
    _create_canonical_file(evidence_root, output_path, evidence)
    return verify_gate_evidence_file(evidence_root, output_path)


def verify_gate_evidence_file(
    evidence_root: Path, evidence_relative_path: str
) -> Mapping[str, object]:
    relative = _relative_path(evidence_relative_path, label="gate evidence path")
    root = _evidence_root(evidence_root)
    document, raw = _canonical_json_file(root, relative)
    role = _identifier(document.get("gate_role"), label="gate_role")
    if role in STAGE5_GATE_ROLES:
        expected_roles = STAGE5_GATE_ROLES
    elif role in STAGE6_GATE_ROLES:
        expected_roles = STAGE6_GATE_ROLES
    else:
        raise ReleaseClosureError("gate role 不受支持")
    verified = _validate_gate_evidence(
        document,
        root=root,
        relative_path=relative,
        expected_roles=expected_roles,
    )
    document_again, raw_again = _canonical_json_file(root, relative)
    if raw != raw_again or canonical_bytes(verified) != canonical_bytes(document_again):
        raise ReleaseClosureError("gate evidence 在核验期间漂移")
    return verified


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


def _print_document(value: Mapping[str, object]) -> None:
    sys.stdout.write(canonical_bytes(value).decode("utf-8") + "\n")


def _cli_evidence_root(value: Path) -> Path:
    """CLI 只消费/写入生产唯一 D 项目根内的闭包。"""

    root = _evidence_root(value)
    try:
        exact_d = Path(EXACT_VM_PROJECT_ROOT).resolve(strict=True)
        root.relative_to(exact_d)
    except (OSError, ValueError) as error:
        raise ReleaseClosureError("CLI evidence-root 必须位于 exact D project root 内") from error
    return root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    derive = commands.add_parser(
        "derive-gate", help="从 typed observation 派生 create-only gate evidence"
    )
    derive.add_argument("--evidence-root", type=Path, required=True)
    derive.add_argument("--observation", required=True)
    derive.add_argument("--output", required=True)

    verify_gate = commands.add_parser("verify-gate", help="重放一个 gate evidence")
    verify_gate.add_argument("--evidence-root", type=Path, required=True)
    verify_gate.add_argument("--gate", required=True)

    certify = commands.add_parser(
        "certify-stage5", help="重放十类 Stage 5 gate 并签发 create-only certificate"
    )
    certify.add_argument("--evidence-root", type=Path, required=True)
    certify.add_argument("--gate", action="append", required=True)
    certify.add_argument("--output", required=True)

    verify_stage5 = commands.add_parser(
        "verify-stage5", help="重放 Stage 5 certificate 及全部底层 evidence"
    )
    verify_stage5.add_argument("--evidence-root", type=Path, required=True)
    verify_stage5.add_argument("--certificate", required=True)

    visibility = commands.add_parser(
        "close-visibility", help="重放五类 Private gate 并签发 visibility receipt"
    )
    visibility.add_argument("--evidence-root", type=Path, required=True)
    visibility.add_argument("--stage5-certificate", required=True)
    visibility.add_argument("--gate", action="append", required=True)
    visibility.add_argument("--output", required=True)

    verify_visibility = commands.add_parser(
        "verify-visibility", help="重放 visibility receipt、Stage 5 与全部底层 evidence"
    )
    verify_visibility.add_argument("--evidence-root", type=Path, required=True)
    verify_visibility.add_argument("--receipt", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        evidence_root = _cli_evidence_root(args.evidence_root)
        if args.command == "derive-gate":
            result = write_gate_evidence_from_observation(
                evidence_root,
                args.observation,
                output_path=args.output,
            )
        elif args.command == "verify-gate":
            result = verify_gate_evidence_file(evidence_root, args.gate)
        elif args.command == "certify-stage5":
            result = write_stage5_release_certificate(
                evidence_root,
                args.gate,
                output_path=args.output,
            )
        elif args.command == "verify-stage5":
            result = verify_stage5_release_certificate_file(
                evidence_root, args.certificate
            )
        elif args.command == "close-visibility":
            result = write_visibility_closure_receipt(
                evidence_root,
                stage5_certificate_path=args.stage5_certificate,
                evidence_paths=args.gate,
                output_path=args.output,
            )
        elif args.command == "verify-visibility":
            result = verify_visibility_closure_receipt_file(
                evidence_root, args.receipt
            )
        else:  # pragma: no cover - argparse guarantees a supported command.
            parser.error("unsupported command")
            return 2
    except ReleaseClosureError as error:
        sys.stderr.write(f"release closure failed: {error}\n")
        return 2
    _print_document(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
