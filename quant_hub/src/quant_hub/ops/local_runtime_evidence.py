"""B3 本地部署运行证据的纯 closed-schema 合同。

本模块只验证和规范化可持久证据；它不打开数据库、不探测服务，也不创建任何
资格 capability。state seal 的 ``canonical_path`` 只允许固定 D state（或显式
test-only root）机械观察值；其他证据不保存 URI、fd、handle 或 authority token。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Callable, Mapping

from .local_release_identity import canonical_bytes, identity_sha256


SQLITE_COMPATIBILITY_MANIFEST_SCHEMA = "qrh-sqlite-compatibility-manifest/v1"
STATE_DATABASE_SEAL_SCHEMA = "qrh-state-database-seal/v1"
ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA = "qrh-isolated-sqlite-copy/v1"
DEPLOYMENT_CANARY_EVIDENCE_SCHEMA = "qrh-deployment-canary-evidence/v1"

_DATABASE_VERSIONS = {"comments": 2, "research_workspace": 3}
_OPERATIONS = {"activate_successor", "rollback_to_prior", "bootstrap_first_pair"}
_PRODUCTION_STATE_PATHS = {
    "comments": r"D:\quant\quant_platform\state\comments.sqlite3",
    "research_workspace": r"D:\quant\quant_platform\state\research_workspace.sqlite3",
}
_WORKSPACE_MIGRATIONS = (
    (
        1,
        "research_workspace",
        "23342bf329cf9164987ed636f37858c2802ed9c3e2a36c045c967c927af6df4b",
        "991a1c21dca347bd8d8615abaf50b365871079bc24aa6667d38c28c403601ecd",
    ),
    (
        2,
        "project_semantics",
        "e72a07ea4adfca987ceffaf58b30bfa36958e3e816b977c09f943f08de6fe0a5",
        "686e2f587de39485de4c8c41e8a4fc0fe7c150a8aad07b63a3521356b8c7c4c2",
    ),
    (
        3,
        "project_creation_command",
        "bc77fd306e193466a4af48fa2c16086a69167e1a07bfefed17f400d1d420c387",
        "b0e4c172b41fe914076a10768af1e74c3e970c2529624a55a2c52491be8c14f1",
    ),
)
_BUSINESS_TABLES = {
    "comments": (
        "actor",
        "command_receipt",
        "comment",
        "comment_event",
        "comment_target",
        "legacy_import_run",
        "outbox_event",
        "progress_command_receipt",
        "progress_topic",
        "progress_topic_event",
    ),
    "research_workspace": (
        "actor",
        "research_workspace_command_receipt",
        "research_workspace_comment",
        "research_workspace_comment_event",
        "research_workspace_event",
        "research_workspace_node",
        "research_workspace_observation",
        "research_workspace_sync_run",
    ),
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class LocalRuntimeEvidenceError(RuntimeError):
    """运行证据不是 closed、canonical 或内部一致时抛出。"""


def _clone(value: object, *, label: str) -> dict[str, object]:
    try:
        cloned = json.loads(canonical_bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LocalRuntimeEvidenceError(f"{label} 不是 canonical JSON") from error
    if type(cloned) is not dict:
        raise LocalRuntimeEvidenceError(f"{label} 必须是 JSON object")
    return cloned


def _closed(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise LocalRuntimeEvidenceError(f"{label} schema 不闭合")
    return value


def _reject_path_leaks(value: object, *, label: str) -> None:
    """拒绝证据中可被误当作路径 authority 的文本。"""

    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise LocalRuntimeEvidenceError(f"{label} key 类型错误")
            lowered = key.casefold()
            if key != "canonical_path" and any(
                token in lowered for token in ("path", "directory", "filename", "uri")
            ):
                raise LocalRuntimeEvidenceError(f"{label} 不得包含路径字段")
            _reject_path_leaks(child, label=label)
        return
    if type(value) is list:
        for child in value:
            _reject_path_leaks(child, label=label)
        return
    # closed schema 中只有 canonical_path 可携带路径；它在对应 validator
    # 中绑定 exact 产品 D state 或显式 test-only root。其余字符串由 enum、
    # identifier、SHA 或固定 result validator 继续收紧。


def _text(value: object, *, label: str, maximum: int = 200) -> str:
    if type(value) is not str or not value or len(value) > maximum or value != value.strip():
        raise LocalRuntimeEvidenceError(f"{label} 文本无效")
    return value


def _identifier(value: object, *, label: str) -> str:
    text = _text(value, label=label, maximum=180)
    if _IDENTIFIER_RE.fullmatch(text) is None:
        raise LocalRuntimeEvidenceError(f"{label} identifier 无效")
    if text.endswith((".", " ")) or text.split(".", 1)[0].casefold() in _WINDOWS_RESERVED:
        raise LocalRuntimeEvidenceError(f"{label} 是 Windows 非安全 identifier")
    return text


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise LocalRuntimeEvidenceError(f"{label} 必须是 >= {minimum} 的整数")
    return value


def _sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None or value == "0" * 64:
        raise LocalRuntimeEvidenceError(f"{label} SHA-256 无效")
    return value


def _database_name(value: object) -> str:
    if value not in _DATABASE_VERSIONS:
        raise LocalRuntimeEvidenceError("database_name 只允许 comments/research_workspace")
    return str(value)


def _operation(value: object) -> str:
    if value not in _OPERATIONS:
        raise LocalRuntimeEvidenceError("operation 不属于本地 pair 部署状态机")
    return str(value)


def _versions(value: object, *, label: str) -> list[int]:
    if (
        type(value) is not list
        or not value
        or any(type(item) is not int or item < 1 for item in value)
        or value != sorted(set(value))
    ):
        raise LocalRuntimeEvidenceError(f"{label} 必须是有序、去重的正整数列表")
    return value


def _migration_entry(value: object, *, label: str) -> dict[str, object]:
    entry = _closed(
        value,
        {"version", "name", "up_sha256", "down_sha256"},
        label=label,
    )
    _integer(entry["version"], label=f"{label}.version", minimum=1)
    _identifier(entry["name"], label=f"{label}.name")
    _sha256(entry["up_sha256"], label=f"{label}.up_sha256")
    _sha256(entry["down_sha256"], label=f"{label}.down_sha256")
    return entry


def _migration_ledger(value: object, *, database_name: str) -> list[object]:
    if type(value) is not list:
        raise LocalRuntimeEvidenceError("migration_ledger 必须是 list")
    if database_name == "comments":
        if value:
            raise LocalRuntimeEvidenceError("comments 不得伪造 migration ledger")
        return value
    for index, raw in enumerate(value, start=1):
        entry = _migration_entry(raw, label=f"migration_ledger[{index}]")
        if entry["version"] != index:
            raise LocalRuntimeEvidenceError("workspace migration ledger 必须连续 1..3")
    observed = tuple(
        (
            entry["version"],
            entry["name"],
            entry["up_sha256"],
            entry["down_sha256"],
        )
        for entry in value
    )
    if observed != _WORKSPACE_MIGRATIONS:
        raise LocalRuntimeEvidenceError("workspace migration ledger 与 exact 1..3 closure 不同")
    return value


def _verify_self_hash(document: Mapping[str, object], *, field: str, label: str) -> None:
    claimed = _sha256(document[field], label=f"{label}.{field}")
    material = dict(document)
    material.pop(field)
    if identity_sha256(material) != claimed:
        raise LocalRuntimeEvidenceError(f"{label} 自身 hash 不匹配")


def validate_sqlite_compatibility_manifest(value: object) -> dict[str, object]:
    manifest = _closed(
        value,
        {
            "schema_version",
            "operation",
            "database_name",
            "logical_schema_version",
            "qualification_scope",
            "candidate_compatibility",
            "prior_compatibility",
            "rollback_policy",
            "schema_contract_sha256",
            "manifest_sha256",
        },
        label="SQLite compatibility manifest",
    )
    _reject_path_leaks(manifest, label="SQLite compatibility manifest")
    if manifest["schema_version"] != SQLITE_COMPATIBILITY_MANIFEST_SCHEMA:
        raise LocalRuntimeEvidenceError("SQLite compatibility schema_version 不同")
    _operation(manifest["operation"])
    database = _database_name(manifest["database_name"])
    if manifest["qualification_scope"] != "diagnostic_only_unresolved_release_closure":
        raise LocalRuntimeEvidenceError("B3a compatibility 不得冒充 formal release closure")
    logical = _integer(
        manifest["logical_schema_version"],
        label="logical_schema_version",
        minimum=1,
    )
    if logical != _DATABASE_VERSIONS[database]:
        raise LocalRuntimeEvidenceError("logical schema version 与数据库不同")
    release_refs: list[tuple[str, str]] = []
    roles = ("candidate",) if manifest["operation"] == "bootstrap_first_pair" else ("candidate", "prior")
    if manifest["operation"] == "bootstrap_first_pair":
        absent_prior = _closed(
            manifest["prior_compatibility"],
            {"status"},
            label="bootstrap prior compatibility",
        )
        if absent_prior["status"] != "absent":
            raise LocalRuntimeEvidenceError("bootstrap prior compatibility must be absent")
    for role in roles:
        compatibility = _closed(
            manifest[f"{role}_compatibility"],
            {"release_id", "release_manifest_sha256", "read_versions", "write_versions"},
            label=f"{role} compatibility",
        )
        release_id = _identifier(compatibility["release_id"], label=f"{role}.release_id")
        release_hash = _sha256(
            compatibility["release_manifest_sha256"],
            label=f"{role}.release_manifest_sha256",
        )
        read = _versions(compatibility["read_versions"], label=f"{role}.read_versions")
        write = _versions(compatibility["write_versions"], label=f"{role}.write_versions")
        if logical not in read or logical not in write:
            raise LocalRuntimeEvidenceError(f"{role} compatibility 未包含当前逻辑 schema")
        release_refs.append((release_id.casefold(), release_hash))
    if len(release_refs) == 2 and (
        release_refs[0][0] == release_refs[1][0]
        or release_refs[0][1] == release_refs[1][1]
    ):
        raise LocalRuntimeEvidenceError("candidate/prior compatibility 必须绑定不同 release")
    if manifest["rollback_policy"] != "expand_only_no_down_migration":
        raise LocalRuntimeEvidenceError("compatibility 必须 expand-only/no-down-migration")
    _sha256(manifest["schema_contract_sha256"], label="schema_contract_sha256")
    _verify_self_hash(manifest, field="manifest_sha256", label="SQLite compatibility manifest")
    return _clone(manifest, label="SQLite compatibility manifest")


def build_sqlite_compatibility_manifest(
    *,
    operation: str,
    database_name: str,
    logical_schema_version: int,
    candidate_release_id: str,
    candidate_release_manifest_sha256: str,
    candidate_read_versions: list[int],
    candidate_write_versions: list[int],
    prior_release_id: str | None,
    prior_release_manifest_sha256: str | None,
    prior_read_versions: list[int] | None,
    prior_write_versions: list[int] | None,
    schema_contract_sha256: str,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": SQLITE_COMPATIBILITY_MANIFEST_SCHEMA,
        "operation": operation,
        "database_name": database_name,
        "logical_schema_version": logical_schema_version,
        "qualification_scope": "diagnostic_only_unresolved_release_closure",
        "candidate_compatibility": {
            "release_id": candidate_release_id,
            "release_manifest_sha256": candidate_release_manifest_sha256,
            "read_versions": list(candidate_read_versions),
            "write_versions": list(candidate_write_versions),
        },
        "prior_compatibility": (
            {"status": "absent"}
            if operation == "bootstrap_first_pair"
            else {
                "release_id": prior_release_id,
                "release_manifest_sha256": prior_release_manifest_sha256,
                "read_versions": list(prior_read_versions or []),
                "write_versions": list(prior_write_versions or []),
            }
        ),
        "rollback_policy": "expand_only_no_down_migration",
        "schema_contract_sha256": schema_contract_sha256,
    }
    if operation != "bootstrap_first_pair" and any(
        value is None
        for value in (
            prior_release_id,
            prior_release_manifest_sha256,
            prior_read_versions,
            prior_write_versions,
        )
    ):
        raise LocalRuntimeEvidenceError("ordinary compatibility requires prior release material")
    document["manifest_sha256"] = identity_sha256(document)
    return validate_sqlite_compatibility_manifest(document)


def _logical_schema(value: object, *, database_name: str) -> dict[str, object]:
    logical = _closed(
        value,
        {"logical_version", "comment_store_schema", "comment_target_schema"},
        label="logical_schema",
    )
    version = _integer(logical["logical_version"], label="logical_version", minimum=1)
    if version != _DATABASE_VERSIONS[database_name]:
        raise LocalRuntimeEvidenceError("logical schema evidence 版本错误")
    for field in ("comment_store_schema", "comment_target_schema"):
        if type(logical[field]) is not list or any(type(item) is not int for item in logical[field]):
            raise LocalRuntimeEvidenceError(f"{field} 必须是整数列表")
    expected = ([1, 2], [3]) if database_name == "comments" else ([], [])
    if (logical["comment_store_schema"], logical["comment_target_schema"]) != expected:
        raise LocalRuntimeEvidenceError("comments marker 或 workspace 空 marker 不匹配")
    return logical


def _file_observation(value: object, *, label: str) -> dict[str, object]:
    observation = _closed(
        value,
        {
            "identity_scheme",
            "bytes",
            "mtime_ns",
            "bytes_sha256",
            "volume_identity_sha256",
            "file_identity_sha256",
        },
        label=label,
    )
    if observation["identity_scheme"] not in {"windows_file_id", "posix_test_only"}:
        raise LocalRuntimeEvidenceError(f"{label}.identity_scheme 无效")
    _integer(observation["bytes"], label=f"{label}.bytes")
    _integer(observation["mtime_ns"], label=f"{label}.mtime_ns")
    for field in ("bytes_sha256", "volume_identity_sha256", "file_identity_sha256"):
        _sha256(observation[field], label=f"{label}.{field}")
    return observation


def _file_set(
    value: object,
    *,
    open_mode: str,
    database_path: str,
) -> list[object]:
    if type(value) is not list or len(value) != 3:
        raise LocalRuntimeEvidenceError("file_set 必须恰含 main/wal/shm")
    expected_presence = (
        ["present", "absent", "absent"]
        if open_mode == "main_only_immutable"
        else ["present", "present", "present"]
    )
    for index, (raw, role, presence) in enumerate(
        zip(value, ("main", "wal", "shm"), expected_presence, strict=True)
    ):
        member = _closed(
            raw,
            {"role", "canonical_path", "presence", "before", "after"},
            label=f"file_set[{index}]",
        )
        expected_path = database_path + {"main": "", "wal": "-wal", "shm": "-shm"}[role]
        if (
            member["role"] != role
            or member["canonical_path"] != expected_path
            or member["presence"] != presence
        ):
            raise LocalRuntimeEvidenceError("file_set role/presence 与 open mode 不匹配")
        if presence == "absent":
            if member["before"] is not None or member["after"] is not None:
                raise LocalRuntimeEvidenceError("absent SQLite member 不得有观察")
            continue
        before = _file_observation(member["before"], label=f"file_set[{index}].before")
        after = _file_observation(member["after"], label=f"file_set[{index}].after")
        if before != after:
            raise LocalRuntimeEvidenceError("SQLite member 前后身份/字节漂移")
    return value


def _business_summary(value: object) -> dict[str, object]:
    summary = _closed(
        value,
        {"metrics", "table_digests", "logical_content_sha256", "summary_sha256"},
        label="business_summary",
    )
    metrics = summary["metrics"]
    if type(metrics) is not list:
        raise LocalRuntimeEvidenceError("business metrics 必须是 list")
    names: list[str] = []
    for index, raw in enumerate(metrics):
        metric = _closed(raw, {"metric", "value"}, label=f"metric[{index}]")
        names.append(_identifier(metric["metric"], label=f"metric[{index}].metric"))
        _integer(metric["value"], label=f"metric[{index}].value")
    if names != sorted(set(names)):
        raise LocalRuntimeEvidenceError("business metrics 必须按名称排序且去重")
    table_digests = summary["table_digests"]
    if type(table_digests) is not list:
        raise LocalRuntimeEvidenceError("business table digests 必须是 list")
    table_names: list[str] = []
    for index, raw in enumerate(table_digests):
        table = _closed(
            raw,
            {"table", "row_count", "rows_sha256"},
            label=f"table_digest[{index}]",
        )
        table_names.append(_identifier(table["table"], label=f"table_digest[{index}].table"))
        _integer(table["row_count"], label=f"table_digest[{index}].row_count")
        _sha256(table["rows_sha256"], label=f"table_digest[{index}].rows_sha256")
    if table_names != sorted(set(table_names)):
        raise LocalRuntimeEvidenceError("business table digests 必须按表名排序且去重")
    logical_hash = _sha256(summary["logical_content_sha256"], label="logical_content_sha256")
    _sha256(summary["summary_sha256"], label="summary_sha256")
    if summary["summary_sha256"] != identity_sha256(
        {
            "metrics": metrics,
            "table_digests": table_digests,
            "logical_content_sha256": logical_hash,
        }
    ):
        raise LocalRuntimeEvidenceError("business summary hash 不匹配")
    return summary


def validate_state_database_seal(
    value: object,
    *,
    for_test_only_root: str | None = None,
) -> dict[str, object]:
    seal = _closed(
        value,
        {
            "schema_version",
            "attempt_id",
            "nonce",
            "operation",
            "database_name",
            "qualification_scope",
            "runtime_scope",
            "canonical_path",
            "state_identity_sha256",
            "open_mode",
            "raw_user_version",
            "logical_schema",
            "migration_ledger",
            "sqlite_schema_sha256",
            "integrity_check",
            "quick_check",
            "foreign_key_violation_count",
            "business_summary",
            "file_set",
            "compatibility_manifest_sha256",
            "result",
            "seal_sha256",
        },
        label="state database seal",
    )
    _reject_path_leaks(seal, label="state database seal")
    if seal["schema_version"] != STATE_DATABASE_SEAL_SCHEMA:
        raise LocalRuntimeEvidenceError("state database seal schema_version 不同")
    _identifier(seal["attempt_id"], label="attempt_id")
    _identifier(seal["nonce"], label="nonce")
    _operation(seal["operation"])
    database = _database_name(seal["database_name"])
    if seal["qualification_scope"] != "diagnostic_only_unresolved_release_closure":
        raise LocalRuntimeEvidenceError("B3a state seal 不得冒充 formal qualification")
    if for_test_only_root is None:
        if seal["runtime_scope"] != "production_exact_d":
            raise LocalRuntimeEvidenceError("产品 seal 必须绑定 production_exact_d")
        expected_database_path = _PRODUCTION_STATE_PATHS[database]
    else:
        if seal["runtime_scope"] != "test_only_explicit_root":
            raise LocalRuntimeEvidenceError("test seal 必须显式标识 test-only scope")
        separator = "\\" if "\\" in for_test_only_root else "/"
        expected_database_path = (
            for_test_only_root.rstrip("\\/")
            + separator
            + "state"
            + separator
            + ("comments.sqlite3" if database == "comments" else "research_workspace.sqlite3")
        )
    if seal["canonical_path"] != expected_database_path:
        raise LocalRuntimeEvidenceError("state seal canonical_path 不属于 exact runtime state")
    _sha256(seal["state_identity_sha256"], label="state_identity_sha256")
    if seal["open_mode"] not in {"main_only_immutable", "wal_triplet_read_only"}:
        raise LocalRuntimeEvidenceError("SQLite open mode 无效")
    _integer(seal["raw_user_version"], label="raw_user_version")
    _logical_schema(seal["logical_schema"], database_name=database)
    _migration_ledger(seal["migration_ledger"], database_name=database)
    _sha256(seal["sqlite_schema_sha256"], label="sqlite_schema_sha256")
    if (
        seal["integrity_check"] != "ok"
        or seal["quick_check"] != "ok"
        or seal["foreign_key_violation_count"] != 0
    ):
        raise LocalRuntimeEvidenceError("SQLite quick/FK 检查未闭合")
    summary = _business_summary(seal["business_summary"])
    if tuple(item["table"] for item in summary["table_digests"]) != _BUSINESS_TABLES[database]:
        raise LocalRuntimeEvidenceError("business table digest 集合不闭合")
    _file_set(
        seal["file_set"],
        open_mode=str(seal["open_mode"]),
        database_path=expected_database_path,
    )
    _sha256(seal["compatibility_manifest_sha256"], label="compatibility_manifest_sha256")
    if seal["result"] != "read_only_observation":
        raise LocalRuntimeEvidenceError("state seal 不得自报资格结果")
    _verify_self_hash(seal, field="seal_sha256", label="state database seal")
    return _clone(seal, label="state database seal")


def build_state_database_seal(
    payload: Mapping[str, object],
    *,
    for_test_only_root: str | None = None,
) -> dict[str, object]:
    document = dict(payload)
    if "seal_sha256" in document:
        raise LocalRuntimeEvidenceError("state seal payload 不得预置 seal_sha256")
    document["seal_sha256"] = identity_sha256(document)
    return validate_state_database_seal(document, for_test_only_root=for_test_only_root)


def validate_isolated_sqlite_copy_evidence(value: object) -> dict[str, object]:
    evidence = _closed(
        value,
        {
            "schema_version",
            "attempt_id",
            "nonce",
            "operation",
            "database_name",
            "state_identity_sha256",
            "compatibility_manifest_sha256",
            "source_seal_sha256",
            "sqlite_main_bytes",
            "sqlite_main_sha256",
            "destination_members",
            "destination_integrity_check",
            "destination_quick_check",
            "destination_foreign_key_violation_count",
            "destination_schema_sha256",
            "destination_business_summary_sha256",
            "result",
            "evidence_sha256",
        },
        label="isolated SQLite copy evidence",
    )
    _reject_path_leaks(evidence, label="isolated SQLite copy evidence")
    if evidence["schema_version"] != ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA:
        raise LocalRuntimeEvidenceError("isolated copy schema_version 不同")
    _identifier(evidence["attempt_id"], label="attempt_id")
    _identifier(evidence["nonce"], label="nonce")
    _operation(evidence["operation"])
    _database_name(evidence["database_name"])
    _sha256(evidence["state_identity_sha256"], label="state_identity_sha256")
    _sha256(
        evidence["compatibility_manifest_sha256"],
        label="compatibility_manifest_sha256",
    )
    _sha256(evidence["source_seal_sha256"], label="source_seal_sha256")
    _integer(evidence["sqlite_main_bytes"], label="sqlite_main_bytes", minimum=1)
    for field in (
        "sqlite_main_sha256",
        "destination_schema_sha256",
        "destination_business_summary_sha256",
    ):
        _sha256(evidence[field], label=field)
    if evidence["destination_members"] != ["main"]:
        raise LocalRuntimeEvidenceError("isolated copy 必须合成为单一 main")
    if (
        evidence["destination_integrity_check"] != "ok"
        or evidence["destination_quick_check"] != "ok"
        or evidence["destination_foreign_key_violation_count"] != 0
        or evidence["result"] != "isolated_copy_verified"
    ):
        raise LocalRuntimeEvidenceError("isolated copy 验证未闭合")
    _verify_self_hash(evidence, field="evidence_sha256", label="isolated SQLite copy evidence")
    return _clone(evidence, label="isolated SQLite copy evidence")


def build_isolated_sqlite_copy_evidence(payload: Mapping[str, object]) -> dict[str, object]:
    document = dict(payload)
    if "evidence_sha256" in document:
        raise LocalRuntimeEvidenceError("copy evidence payload 不得预置 hash")
    document["evidence_sha256"] = identity_sha256(document)
    return validate_isolated_sqlite_copy_evidence(document)


def _challenge(value: object) -> dict[str, object]:
    challenge = _closed(
        value,
        {
            "initial_revision",
            "applied_from_revision",
            "applied_to_revision",
            "applied_rowcount",
            "stale_from_revision",
            "stale_to_revision",
            "stale_rowcount",
            "readback_revision",
            "append_only_event_count",
            "event_update_outcome",
            "event_delete_outcome",
        },
        label="deployment challenge",
    )
    expected = {
        "initial_revision": 0,
        "applied_from_revision": 0,
        "applied_to_revision": 1,
        "applied_rowcount": 1,
        "stale_from_revision": 0,
        "stale_to_revision": 2,
        "stale_rowcount": 0,
        "readback_revision": 1,
        "append_only_event_count": 1,
        "event_update_outcome": "rejected_by_trigger",
        "event_delete_outcome": "rejected_by_trigger",
    }
    if challenge != expected:
        raise LocalRuntimeEvidenceError("deployment challenge 不是 exact SQL CAS 证据")
    return challenge


def _business_probe(value: object, *, database_name: str) -> dict[str, object]:
    probe = _closed(
        value,
        {
            "family",
            "create_rowcount",
            "idempotent_replay_rowcount",
            "edit_rowcount",
            "soft_delete_rowcount",
            "final_revision",
            "event_count",
            "receipt_count",
            "deleted_row_count",
            "before_summary_sha256",
            "after_summary_sha256",
        },
        label="business probe",
    )
    expected_family = "archive_comments" if database_name == "comments" else "workspace_comments"
    if probe["family"] != expected_family:
        raise LocalRuntimeEvidenceError("business probe family 与数据库不同")
    expected_counts = {
        "create_rowcount": 1,
        "idempotent_replay_rowcount": 0,
        "edit_rowcount": 1,
        "soft_delete_rowcount": 1,
        "final_revision": 3,
        "event_count": 3,
        "receipt_count": 3,
        "deleted_row_count": 1,
    }
    for field, expected in expected_counts.items():
        if probe[field] != expected:
            raise LocalRuntimeEvidenceError(f"business probe {field} 不闭合")
    _sha256(probe["before_summary_sha256"], label="before_summary_sha256")
    _sha256(probe["after_summary_sha256"], label="after_summary_sha256")
    return probe


def validate_deployment_canary_evidence(value: object) -> dict[str, object]:
    evidence = _closed(
        value,
        {
            "schema_version",
            "attempt_id",
            "nonce",
            "operation",
            "database_name",
            "state_identity_sha256",
            "compatibility_manifest_sha256",
            "execution_lane",
            "qualification_scope",
            "copy_evidence_sha256",
            "challenge",
            "business_probe",
            "final_main_bytes",
            "final_main_sha256",
            "final_schema_sha256",
            "final_business_summary_sha256",
            "result",
            "evidence_sha256",
        },
        label="deployment canary evidence",
    )
    _reject_path_leaks(evidence, label="deployment canary evidence")
    if evidence["schema_version"] != DEPLOYMENT_CANARY_EVIDENCE_SCHEMA:
        raise LocalRuntimeEvidenceError("deployment canary schema_version 不同")
    _identifier(evidence["attempt_id"], label="attempt_id")
    _identifier(evidence["nonce"], label="nonce")
    _operation(evidence["operation"])
    database = _database_name(evidence["database_name"])
    _sha256(evidence["state_identity_sha256"], label="state_identity_sha256")
    _sha256(
        evidence["compatibility_manifest_sha256"],
        label="compatibility_manifest_sha256",
    )
    if (
        evidence["execution_lane"] != "controller_sql_fixture"
        or evidence["qualification_scope"] != "diagnostic_only_not_exact_release"
    ):
        raise LocalRuntimeEvidenceError("B3a canary 不得冒充 exact-release 资格")
    _sha256(evidence["copy_evidence_sha256"], label="copy_evidence_sha256")
    _challenge(evidence["challenge"])
    probe = _business_probe(evidence["business_probe"], database_name=database)
    if probe["before_summary_sha256"] == probe["after_summary_sha256"]:
        raise LocalRuntimeEvidenceError("business probe 没有形成真实逻辑变化")
    _integer(evidence["final_main_bytes"], label="final_main_bytes", minimum=1)
    for field in (
        "final_main_sha256",
        "final_schema_sha256",
        "final_business_summary_sha256",
    ):
        _sha256(evidence[field], label=field)
    if evidence["final_business_summary_sha256"] != probe["after_summary_sha256"]:
        raise LocalRuntimeEvidenceError("final business summary 未绑定 probe 终态")
    if evidence["result"] != "controller_fixture_verified":
        raise LocalRuntimeEvidenceError("B3a canary result 无效")
    _verify_self_hash(evidence, field="evidence_sha256", label="deployment canary evidence")
    return _clone(evidence, label="deployment canary evidence")


def build_deployment_canary_evidence(payload: Mapping[str, object]) -> dict[str, object]:
    document = dict(payload)
    if "evidence_sha256" in document:
        raise LocalRuntimeEvidenceError("canary evidence payload 不得预置 hash")
    document["evidence_sha256"] = identity_sha256(document)
    return validate_deployment_canary_evidence(document)


@dataclass(frozen=True, slots=True)
class _TypedCanonicalEvidence:
    _raw: bytes

    @classmethod
    def _from_document(
        cls,
        value: object,
        validator: Callable[[object], dict[str, object]],
    ) -> "_TypedCanonicalEvidence":
        validated = validator(value)
        return cls(canonical_bytes(validated))

    def as_dict(self) -> dict[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        assert type(value) is dict
        return value

    def canonical_bytes(self) -> bytes:
        return bytes(self._raw)


@dataclass(frozen=True, slots=True)
class SqliteCompatibilityManifest(_TypedCanonicalEvidence):
    @classmethod
    def from_document(cls, value: object) -> "SqliteCompatibilityManifest":
        return cls._from_document(value, validate_sqlite_compatibility_manifest)  # type: ignore[return-value]

    @property
    def manifest_sha256(self) -> str:
        return str(self.as_dict()["manifest_sha256"])


@dataclass(frozen=True, slots=True)
class StateDatabaseSeal(_TypedCanonicalEvidence):
    @classmethod
    def from_document(cls, value: object) -> "StateDatabaseSeal":
        return cls._from_document(value, validate_state_database_seal)  # type: ignore[return-value]

    @classmethod
    def from_test_document(
        cls,
        value: object,
        *,
        test_root: str,
    ) -> "StateDatabaseSeal":
        validated = validate_state_database_seal(value, for_test_only_root=test_root)
        return cls(canonical_bytes(validated))

    @property
    def seal_sha256(self) -> str:
        return str(self.as_dict()["seal_sha256"])


@dataclass(frozen=True, slots=True)
class IsolatedSqliteCopyEvidence(_TypedCanonicalEvidence):
    @classmethod
    def from_document(cls, value: object) -> "IsolatedSqliteCopyEvidence":
        return cls._from_document(value, validate_isolated_sqlite_copy_evidence)  # type: ignore[return-value]

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


@dataclass(frozen=True, slots=True)
class DeploymentCanaryEvidence(_TypedCanonicalEvidence):
    @classmethod
    def from_document(cls, value: object) -> "DeploymentCanaryEvidence":
        return cls._from_document(value, validate_deployment_canary_evidence)  # type: ignore[return-value]

    @property
    def evidence_sha256(self) -> str:
        return str(self.as_dict()["evidence_sha256"])


__all__ = [
    "DEPLOYMENT_CANARY_EVIDENCE_SCHEMA",
    "ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA",
    "SQLITE_COMPATIBILITY_MANIFEST_SCHEMA",
    "STATE_DATABASE_SEAL_SCHEMA",
    "DeploymentCanaryEvidence",
    "IsolatedSqliteCopyEvidence",
    "LocalRuntimeEvidenceError",
    "SqliteCompatibilityManifest",
    "StateDatabaseSeal",
    "build_deployment_canary_evidence",
    "build_isolated_sqlite_copy_evidence",
    "build_sqlite_compatibility_manifest",
    "build_state_database_seal",
    "validate_deployment_canary_evidence",
    "validate_isolated_sqlite_copy_evidence",
    "validate_sqlite_compatibility_manifest",
    "validate_state_database_seal",
]
