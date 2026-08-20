"""已审核运行根的 strict bootstrap 与可审计恢复契约。

这里的 receipt 防止误用和无意漂移，不是对拥有整个 workspace 写权限的恶意
主体提供密码学真实性。正式交付仍须由独立 deployment gate 和外部权限边界
提供信任根。
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
from typing import Any, Mapping
from urllib.parse import quote

from quant_hub.archive.contracts import (
    ActorInput,
    ManualTopicCreateInput,
    ManualTopicUpdateInput,
    TopicInput,
)
from quant_hub.ids import stable_sha256
from quant_hub.paper_lab.contracts import EDITABLE_PAPER_FIELDS
from quant_hub.paper_lab.identity import stable_public_id
from quant_hub.platform.reviews import (
    ReviewCertificateSpec,
    review_certificate_material_hash,
)
from quant_hub.runtime_seal import (
    RuntimeSealError,
    assert_material,
    canonical_json,
    database_row_manifest,
    database_state,
    file_identity,
    payload_sha256,
    read_json,
    require_no_sqlite_sidecars,
    runtime_toolchain,
    safe_tree,
    safe_tree_file_state,
    write_atomic_new_json,
)


BOOTSTRAP_RECEIPT_SCHEMA = "qrh-reviewed-runtime-bootstrap-receipt/v1"
BOOTSTRAP_POLICY_VERSION = "qrh-reviewed-runtime-bootstrap-policy/v1"
MUTATION_POLICY_VERSION = "qrh-reviewed-runtime-mutations/v1"
INITIAL_LAUNCH_MODE = "strict"

DATABASE_NAMES = (
    "platform.sqlite3",
    "archive.sqlite3",
    "research_papers.sqlite3",
    "paper_lab.sqlite3",
)
MANAGED_TREE_NAMES = (
    "inbox",
    "objects",
    "paper_lab",
    "replay",
    "research_papers",
    "exports",
)

ARCHIVE_APPEND_TABLES = {
    "actor",
    "comment_event",
    "research_update_annotation_event",
    "research_work_state_event",
    "research_completion_decision",
    "research_completion_review_consumption",
    "topic_state_event",
    "topic_mutation_event",
    "command_receipt",
    "outbox_event",
}
ARCHIVE_MUTABLE_TABLES: dict[str, set[str]] = {
    "comment": {"body", "updated_at", "revision", "deleted_at"},
    "topic": {
        "title",
        "manual_order",
        "retired_at",
        "parent_topic_id",
        "revision",
        "updated_at",
    },
    "topic_projection": {
        "effective_state",
        "summary",
        "research_id",
        "page_url",
        "quick_links_json",
        "source_kind",
        "source_event_id",
        "projection_version",
        "updated_at",
    },
    "research_status_projection": {
        "work_status",
        "work_source_event_id",
        "completion_decision_id",
        "projection_version",
        "updated_at",
    },
    "topic_research_link": {
        "link_kind",
        "dashboard_primary",
        "display_rank",
        "status",
        "provenance_urn",
    },
    "research_update_export_checkpoint": {
        "database_watermark",
        "history_sha256",
        "row_count",
        "exported_at",
    },
}
ARCHIVE_ALLOWED_COMMANDS = {
    "comment.create",
    "comment.update",
    "comment.delete",
    "topic.create_manual",
    "topic.update_manual",
    "topic.retire_manual",
    "topic.set_state",
    "research.set_work_state",
    "topic.create",
    "topic.link_research",
    "research.complete",
    "research.revoke_completion",
    "research_update.annotate",
}
ARCHIVE_COMMAND_REQUEST_FIELDS: dict[str, set[str]] = {
    "comment.create": {"research_id", "actor", "body"},
    "comment.update": {"comment_id", "actor", "content", "expected_revision"},
    "comment.delete": {"comment_id", "actor", "content", "expected_revision"},
    "topic.create_manual": {"topic", "actor"},
    "topic.update_manual": {"topic_id", "changes", "actor", "expected_revision"},
    "topic.retire_manual": {"topic_id", "actor", "expected_revision"},
    "topic.set_state": {"topic_id", "state", "note", "actor"},
    "research.set_work_state": {"research_id", "state", "note", "actor"},
    "topic.create": {"topic", "actor"},
    "topic.link_research": {
        "topic_id",
        "research_id",
        "actor",
        "link_kind",
        "dashboard_primary",
        "display_rank",
        "provenance_urn",
    },
    "research.complete": {
        "research_id",
        "research_release_id",
        "reason",
        "actor",
        "review_urn",
    },
    "research.revoke_completion": {
        "research_id",
        "target_decision_id",
        "reason",
        "actor",
        "review_urn",
    },
    "research_update.annotate": {
        "update_id",
        "actor",
        "note",
        "expected_revision",
    },
}
ARCHIVE_REJECTION_STATUS: dict[str, dict[str, int]] = {
    "comment.create": {"invalid_comment": 422, "research_not_found": 404},
    "comment.update": {"comment_not_found": 404, "revision_conflict": 409, "invalid_comment": 422},
    "comment.delete": {"comment_not_found": 404, "revision_conflict": 409},
    "topic.create_manual": {"invalid_topic_parent": 422},
    "topic.update_manual": {
        "topic_not_found": 404,
        "topic_not_manual": 409,
        "revision_conflict": 409,
        "manual_topic_state_missing": 409,
        "invalid_topic_update": 422,
        "invalid_topic_parent": 422,
    },
    "topic.retire_manual": {
        "topic_not_found": 404,
        "topic_already_retired": 409,
        "topic_not_manual": 409,
        "revision_conflict": 409,
        "topic_has_active_children": 409,
        "topic_has_active_research_links": 409,
    },
    "topic.create": {"topic_key_conflict": 409},
    "topic.link_research": {"topic_or_research_not_found": 404},
    "topic.set_state": {"topic_not_found": 404},
    "research.set_work_state": {"research_not_found": 404},
    "research.complete": {
        "release_not_active": 409,
        "already_completed": 409,
        "review_candidate_incomplete": 409,
        "review_certificate_invalid": 409,
    },
    "research.revoke_completion": {
        "review_certificate_required": 409,
        "completion_not_found": 404,
        "completion_already_revoked": 409,
    },
    "research_update.annotate": {
        "research_update_not_found": 404,
        "invalid_research_update_annotation": 422,
        "revision_conflict": 409,
    },
}
ARCHIVE_APPLIED_STATUS = {
    "comment.create": 201,
    "comment.update": 200,
    "comment.delete": 200,
    "topic.create_manual": 201,
    "topic.update_manual": 200,
    "topic.retire_manual": 200,
    "topic.create": 201,
    "topic.link_research": 200,
    "topic.set_state": 201,
    "research.set_work_state": 201,
    "research.complete": 201,
    "research.revoke_completion": 201,
    "research_update.annotate": 201,
}
ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH = stable_sha256(
    "archive-completion-review-requirements/v1",
    "active-release-bound",
    "frozen-review-artifact",
    "released-summary-required",
    "source-completion-evidence",
)
TOPIC_MANAGEMENT_RESULT_FIELDS = {
    "topic_id", "topic_key", "title", "display_title", "parent_topic_id",
    "parent_title", "depth", "manual_order", "revision", "etag", "is_manual",
    "created_by", "created_at", "updated_at", "retired_at", "retired", "state",
    "manual_state", "state_note", "state_actor", "state_occurred_at", "source_kind",
    "summary", "research_id", "page_url", "quick_links", "projection_updated_at",
    "last_event_kind", "last_modified_by", "last_mutation_at", "active_child_count",
    "active_research_link_count",
}
ARCHIVE_CLOSURE_VALUE_TABLES = {
    "active_research_release",
    "research",
    "research_release",
    "research_release_activation",
    "derived_research_metadata",
    "research_release_candidate_identity",
    "research_update",
}

PLATFORM_CLOSURE_VALUE_TABLES = {"review_certificate"}

PAPER_LAB_APPEND_TABLES = {
    "lab_paper_version",
    "paper_field_overlay",
    "blueprint_version",
    "blueprint_component",
    "paper_lab_event",
    "paper_lab_command_receipt",
}
PAPER_LAB_MUTABLE_TABLES: dict[str, set[str]] = {
    "architecture_blueprint": {"name", "objective", "updated_at"},
    "lab_paper": {"updated_at"},
}
PAPER_LAB_CLOSURE_VALUE_TABLES = {"concept_component", "compatibility_rule"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def bootstrap_receipt_path(project: Path, delivery: Path) -> Path:
    """每个规范化 delivery 唯一、位于 project_state 的固定 receipt 路径。"""

    project = project.resolve(strict=True)
    delivery = delivery.resolve(strict=True)
    identity = hashlib.sha256(str(delivery).casefold().encode("utf-8")).hexdigest()[:20]
    return (
        project
        / "project_state"
        / "runtime"
        / "bootstrap_receipts"
        / f"{delivery.name}-{identity}.json"
    ).resolve(strict=False)


def validate_startup_bootstrap_contract(
    gate: Mapping[str, object],
    *,
    project: Path,
    delivery: Path,
) -> Path:
    if gate.get("initial_launch_mode") != INITIAL_LAUNCH_MODE:
        raise RuntimeSealError("startup gate must declare initial_launch_mode=strict")
    policy = gate.get("bootstrap_receipt_policy")
    if not isinstance(policy, dict):
        raise RuntimeSealError("startup gate has no bootstrap receipt policy")
    if policy.get("policy_version") != BOOTSTRAP_POLICY_VERSION:
        raise RuntimeSealError("startup gate bootstrap policy version is unsupported")
    if policy.get("mutation_policy_version") != MUTATION_POLICY_VERSION:
        raise RuntimeSealError("startup gate mutation policy version is unsupported")
    expected = bootstrap_receipt_path(project, delivery)
    declared = Path(str(policy.get("path", ""))).resolve(strict=False)
    if declared != expected:
        raise RuntimeSealError("startup gate bootstrap receipt path is not canonical")
    if not expected.is_relative_to((project / "project_state").resolve(strict=True)):
        raise RuntimeSealError("bootstrap receipt escaped project_state")
    return expected


def _database_paths(delivery: Path) -> dict[str, Path]:
    return {name: delivery / "db" / name for name in DATABASE_NAMES}


def _mutable_value_tables(name: str) -> tuple[str, ...]:
    if name == "archive.sqlite3":
        return tuple(
            sorted(
                ARCHIVE_APPEND_TABLES
                | set(ARCHIVE_MUTABLE_TABLES)
                | ARCHIVE_CLOSURE_VALUE_TABLES
            )
        )
    if name == "paper_lab.sqlite3":
        return tuple(
            sorted(
                PAPER_LAB_APPEND_TABLES
                | set(PAPER_LAB_MUTABLE_TABLES)
                | PAPER_LAB_CLOSURE_VALUE_TABLES
            )
        )
    if name == "platform.sqlite3":
        return tuple(sorted(PLATFORM_CLOSURE_VALUE_TABLES))
    return ()


def capture_runtime_state(
    *,
    project: Path,
    delivery: Path,
    code_root: Path,
    migrations_root: Path,
    launcher_path: Path,
) -> dict[str, object]:
    database_paths = _database_paths(delivery)
    require_no_sqlite_sidecars(database_paths.values())
    databases: dict[str, object] = {}
    for name, path in database_paths.items():
        databases[name] = {
            "state": database_state(path),
            "row_manifest": database_row_manifest(
                path,
                include_values_for=_mutable_value_tables(name),
            ),
        }
    managed_trees = {
        name: {
            "state": safe_tree(delivery / name),
            "files": safe_tree_file_state(delivery / name),
        }
        for name in MANAGED_TREE_NAMES
    }
    export_files = managed_trees["exports"]["files"]
    if set(export_files) != {"research_update_history.jsonl"}:
        raise RuntimeSealError(
            "managed exports must contain only research_update_history.jsonl"
        )
    ingress = project / "quant_hub" / "paper_lab" / "papers"
    ingress_files = validate_untrusted_paper_ingress(ingress)
    return {
        "launcher": file_identity(launcher_path),
        "code": safe_tree(code_root, exclude_runtime_caches=True),
        "migrations": safe_tree(migrations_root),
        "toolchain": runtime_toolchain(),
        "sources": {
            "archive": safe_tree(project / "reference" / "archive"),
            "proj2": safe_tree(project / "reference" / "proj2"),
        },
        "databases": databases,
        "managed_trees": managed_trees,
        "untrusted_ingress": {
            "path": str(ingress.resolve(strict=True)),
            "files": ingress_files,
            "tree_state": safe_tree(ingress),
            "serving_policy": "never-serve-directly; scanner-copy-receipt-required",
        },
    }


def validate_untrusted_paper_ingress(root: Path) -> dict[str, dict[str, object]]:
    """投递区只接受根目录 PDF、占位文件和唯一的获取审计清单。"""

    files = safe_tree_file_state(root)
    for relative in files:
        path = Path(relative)
        if len(path.parts) != 1:
            raise RuntimeSealError("Paper Lab ingress contains a nested untrusted path")
        if relative in {".gitkeep", "ACQUISITION_MANIFEST.json"}:
            continue
        if path.suffix.casefold() != ".pdf":
            raise RuntimeSealError("Paper Lab ingress contains an unsupported file")
    return files


def _manifest_hashes(state: Mapping[str, object]) -> dict[str, object]:
    databases = state["databases"]
    trees = state["managed_trees"]
    assert isinstance(databases, dict) and isinstance(trees, dict)
    return {
        "database_table_manifest_sha256": {
            name: payload_sha256(value["row_manifest"])
            for name, value in databases.items()
        },
        "managed_file_manifest_sha256": {
            name: payload_sha256(value["files"])
            for name, value in trees.items()
        },
    }


def _allowed_runtime_mutations() -> dict[str, object]:
    return {
        "archive_tables": {
            "append_only": sorted(ARCHIVE_APPEND_TABLES),
            "field_mutable": {
                key: sorted(value) for key, value in ARCHIVE_MUTABLE_TABLES.items()
            },
            "commands": sorted(ARCHIVE_ALLOWED_COMMANDS),
        },
        "paper_lab_tables": {
            "append_only": sorted(PAPER_LAB_APPEND_TABLES),
            "field_mutable": {
                key: sorted(value) for key, value in PAPER_LAB_MUTABLE_TABLES.items()
            },
            "commands": [
                "paper_drop_registered",
                "save_blueprint",
                "save_paper_field",
            ],
        },
        "managed_file_additions": [
            "paper_lab/assets/<sha256-prefix>/<sha256>.pdf:"
            "lab_paper_version+paper_drop_registered-event-closure"
        ],
        "managed_file_mutations": [
            "exports/research_update_history.jsonl:"
            "archive-update-export-checkpoint+database-derived-content"
        ],
    }


def make_bootstrap_receipt(
    *,
    project: Path,
    delivery: Path,
    activation_path: Path,
    startup_gate_path: Path,
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> dict[str, object]:
    assert_material(after, before, label="strict bootstrap pre/post exact state")
    receipt: dict[str, object] = {
        "schema_version": BOOTSTRAP_RECEIPT_SCHEMA,
        "status": "PASS",
        "bootstrap_policy_version": BOOTSTRAP_POLICY_VERSION,
        "mutation_policy_version": MUTATION_POLICY_VERSION,
        "initial_launch_mode": INITIAL_LAUNCH_MODE,
        "delivery_var": str(delivery.resolve(strict=True)),
        "project_root": str(project.resolve(strict=True)),
        "activation_seal": {
            "path": str(activation_path.resolve(strict=True)),
            "sha256": file_identity(activation_path)["sha256"],
        },
        "startup_gate": {
            "path": str(startup_gate_path.resolve(strict=True)),
            "sha256": file_identity(startup_gate_path)["sha256"],
        },
        "runtime_state_before_create_app": before,
        "runtime_state_after_create_app": after,
        "allowed_runtime_mutations": _allowed_runtime_mutations(),
        "generated_at": _utc_now(),
        "run_id": f"run_{uuid.uuid4().hex}",
    }
    receipt.update(_manifest_hashes(before))
    receipt["receipt_id"] = "boot_" + payload_sha256(receipt)
    return receipt


def _receipt_binding(
    receipt: Mapping[str, object],
    *,
    project: Path,
    delivery: Path,
    activation_path: Path,
    startup_gate_path: Path,
) -> None:
    expected_keys = {
        "schema_version",
        "status",
        "bootstrap_policy_version",
        "mutation_policy_version",
        "initial_launch_mode",
        "delivery_var",
        "project_root",
        "activation_seal",
        "startup_gate",
        "runtime_state_before_create_app",
        "runtime_state_after_create_app",
        "allowed_runtime_mutations",
        "database_table_manifest_sha256",
        "managed_file_manifest_sha256",
        "generated_at",
        "run_id",
        "receipt_id",
    }
    if set(receipt) != expected_keys:
        raise RuntimeSealError("bootstrap receipt field set is not canonical")
    if receipt.get("status") != "PASS":
        raise RuntimeSealError("bootstrap receipt is not PASS")
    if receipt.get("bootstrap_policy_version") != BOOTSTRAP_POLICY_VERSION:
        raise RuntimeSealError("bootstrap receipt policy version changed")
    if receipt.get("mutation_policy_version") != MUTATION_POLICY_VERSION:
        raise RuntimeSealError("bootstrap receipt mutation policy changed")
    if receipt.get("initial_launch_mode") != INITIAL_LAUNCH_MODE:
        raise RuntimeSealError("bootstrap receipt was not produced by strict launch")
    before = receipt.get("runtime_state_before_create_app")
    after = receipt.get("runtime_state_after_create_app")
    if not isinstance(before, dict) or before != after:
        raise RuntimeSealError("bootstrap receipt pre/post exact state differs")
    if receipt.get("allowed_runtime_mutations") != _allowed_runtime_mutations():
        raise RuntimeSealError("bootstrap receipt mutation allowlist changed")
    manifest_hashes = _manifest_hashes(before)
    for key, value in manifest_hashes.items():
        if receipt.get(key) != value:
            raise RuntimeSealError(f"bootstrap receipt {key} changed")
    if Path(str(receipt.get("delivery_var", ""))).resolve(strict=True) != delivery:
        raise RuntimeSealError("bootstrap receipt is bound to another delivery")
    if Path(str(receipt.get("project_root", ""))).resolve(strict=True) != project:
        raise RuntimeSealError("bootstrap receipt is bound to another project")
    for key, path in (
        ("activation_seal", activation_path),
        ("startup_gate", startup_gate_path),
    ):
        binding = receipt.get(key)
        if not isinstance(binding, dict):
            raise RuntimeSealError(f"bootstrap receipt omits {key}")
        if Path(str(binding.get("path", ""))).resolve(strict=True) != path:
            raise RuntimeSealError(f"bootstrap receipt {key} path changed")
        if binding.get("sha256") != file_identity(path)["sha256"]:
            raise RuntimeSealError(f"bootstrap receipt {key} hash changed")
        if set(binding) != {"path", "sha256"}:
            raise RuntimeSealError(f"bootstrap receipt {key} binding is not canonical")
    activation = read_json(
        activation_path, schema_version="qrh-activated-delivery-seal/v1"
    )
    baseline_databases = before.get("databases")
    baseline_trees = before.get("managed_trees")
    if not isinstance(baseline_databases, dict) or not isinstance(baseline_trees, dict):
        raise RuntimeSealError("bootstrap receipt baseline structure is invalid")
    for name in DATABASE_NAMES:
        item = baseline_databases.get(name)
        if not isinstance(item, dict) or item.get("state") != activation.get("databases", {}).get(name):
            raise RuntimeSealError("bootstrap database baseline differs from activation")
    for name in MANAGED_TREE_NAMES:
        item = baseline_trees.get(name)
        if not isinstance(item, dict) or item.get("state") != activation.get("managed_trees", {}).get(name):
            raise RuntimeSealError("bootstrap managed-tree baseline differs from activation")
    runtime_contract = activation.get("runtime_contract")
    source_integrity = activation.get("source_integrity")
    if not isinstance(runtime_contract, dict) or not isinstance(source_integrity, dict):
        raise RuntimeSealError("activation runtime/source contract is invalid")
    if (
        before.get("code") != runtime_contract.get("code")
        or before.get("migrations") != runtime_contract.get("migrations")
        or before.get("toolchain") != runtime_contract.get("toolchain")
        or before.get("sources") != source_integrity
    ):
        raise RuntimeSealError("bootstrap runtime/source baseline differs from activation")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("boot_"):
        raise RuntimeSealError("bootstrap receipt id is invalid")
    unsigned = dict(receipt)
    unsigned.pop("receipt_id", None)
    if receipt_id != "boot_" + payload_sha256(unsigned):
        raise RuntimeSealError("bootstrap receipt self-identity changed")


def load_bootstrap_receipt(
    *,
    receipt_path: Path,
    project: Path,
    delivery: Path,
    activation_path: Path,
    startup_gate_path: Path,
) -> dict[str, object]:
    if not receipt_path.is_file():
        raise RuntimeSealError("reviewed runtime has no successful strict bootstrap receipt")
    receipt = read_json(receipt_path, schema_version=BOOTSTRAP_RECEIPT_SCHEMA)
    _receipt_binding(
        receipt,
        project=project,
        delivery=delivery,
        activation_path=activation_path,
        startup_gate_path=startup_gate_path,
    )
    return receipt


def _rows_by_key(table: Mapping[str, object]) -> dict[str, dict[str, object]]:
    if set(table) != {
        "columns",
        "primary_key",
        "key_kind",
        "row_count",
        "rows",
        "manifest_sha256",
    }:
        raise RuntimeSealError("database table manifest field set is invalid")
    rows = table.get("rows")
    if not isinstance(rows, list):
        raise RuntimeSealError("database row manifest has no rows")
    if table.get("row_count") != len(rows):
        raise RuntimeSealError("database row manifest row count is invalid")
    if table.get("manifest_sha256") != payload_sha256(rows):
        raise RuntimeSealError("database row manifest hash is invalid")
    result: dict[str, dict[str, object]] = {}
    value_shape: bool | None = None
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("key"), list):
            raise RuntimeSealError("database row manifest entry is invalid")
        has_values = "values" in row
        if set(row) != ({"key", "row_sha256", "values"} if has_values else {"key", "row_sha256"}):
            raise RuntimeSealError("database row manifest field set is invalid")
        if value_shape is not None and value_shape != has_values:
            raise RuntimeSealError("database row manifest value shape is inconsistent")
        value_shape = has_values
        if has_values:
            values = row["values"]
            if not isinstance(values, list) or row["row_sha256"] != payload_sha256(values):
                raise RuntimeSealError("database row value hash is invalid")
        key = canonical_json(row["key"])
        if key in result:
            raise RuntimeSealError("database row manifest has duplicate keys")
        result[key] = row
    return result


def _row_dict(table: Mapping[str, object], row: Mapping[str, object]) -> dict[str, object]:
    columns = table.get("columns")
    values = row.get("values")
    if not isinstance(columns, list) or not isinstance(values, list):
        raise RuntimeSealError("mutable table manifest omitted row values")
    if len(columns) != len(values):
        raise RuntimeSealError("mutable row width differs from its table manifest")
    return dict(zip((str(value) for value in columns), values, strict=True))


def _compare_database_baseline(
    baseline: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    append_tables: set[str],
    mutable_tables: Mapping[str, set[str]],
    label: str,
) -> dict[str, set[str]]:
    if set(actual) != set(baseline):
        raise RuntimeSealError(f"{label} table set changed")
    additions: dict[str, set[str]] = {}
    for table_name, baseline_value in baseline.items():
        actual_value = actual[table_name]
        if not isinstance(baseline_value, dict) or not isinstance(actual_value, dict):
            raise RuntimeSealError(f"{label} table manifest is invalid: {table_name}")
        if baseline_value.get("columns") != actual_value.get("columns"):
            raise RuntimeSealError(f"{label} table columns changed: {table_name}")
        if baseline_value.get("primary_key") != actual_value.get("primary_key"):
            raise RuntimeSealError(f"{label} table primary key changed: {table_name}")
        if baseline_value.get("key_kind") != actual_value.get("key_kind"):
            raise RuntimeSealError(f"{label} table key kind changed: {table_name}")
        base_rows = _rows_by_key(baseline_value)
        actual_rows = _rows_by_key(actual_value)
        missing = set(base_rows) - set(actual_rows)
        if missing:
            raise RuntimeSealError(f"{label} activation rows were deleted: {table_name}")
        new_keys = set(actual_rows) - set(base_rows)
        if new_keys and table_name not in append_tables and table_name not in mutable_tables:
            raise RuntimeSealError(f"{label} has unauthorized rows: {table_name}")
        additions[table_name] = new_keys
        for key, before in base_rows.items():
            after = actual_rows[key]
            if set(before) != set(after):
                raise RuntimeSealError(
                    f"{label} activation row manifest shape changed: {table_name}:{key}"
                )
            if table_name not in mutable_tables:
                if before.get("row_sha256") != after.get("row_sha256"):
                    raise RuntimeSealError(
                        f"{label} activation row changed: {table_name}:{key}"
                    )
                continue
            before_values = _row_dict(baseline_value, before)
            after_values = _row_dict(actual_value, after)
            allowed = mutable_tables[table_name]
            for column, old_value in before_values.items():
                if column not in allowed and after_values.get(column) != old_value:
                    raise RuntimeSealError(
                        f"{label} immutable field changed: {table_name}.{column}"
                    )
    return additions


def _table_rows(manifest: Mapping[str, object], table: str) -> dict[str, dict[str, object]]:
    value = manifest.get(table)
    if not isinstance(value, dict):
        raise RuntimeSealError(f"required mutation table is missing: {table}")
    return {
        key: _row_dict(value, row) for key, row in _rows_by_key(value).items()
    }


def _new_rows(
    baseline: Mapping[str, object], actual: Mapping[str, object], table: str
) -> list[dict[str, object]]:
    before = _rows_by_key(baseline[table])  # type: ignore[index]
    after = _table_rows(actual, table)
    return [after[key] for key in sorted(set(after) - set(before))]


def _json_object(value: object, *, label: str) -> dict[str, object]:
    try:
        result = json.loads(str(value))
    except json.JSONDecodeError as error:
        raise RuntimeSealError(f"invalid JSON in {label}") from error
    if not isinstance(result, dict):
        raise RuntimeSealError(f"{label} must be a JSON object")
    return result


def _expected_topic_projection(
    topic_id: str, actual: Mapping[str, object]
) -> dict[str, object]:
    links = [
        row
        for row in _table_rows(actual, "topic_research_link").values()
        if row["topic_id"] == topic_id
        and row["status"] == "active"
        and row["link_kind"] == "primary"
    ]
    statuses = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "research_status_projection").values()
    }
    researches = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "research").values()
    }
    active = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "active_research_release").values()
    }
    completed = sorted(
        [row for row in links if statuses.get(str(row["research_id"]), {}).get("work_status") == "completed"],
        key=lambda row: (int(row["display_rank"]), str(row["research_id"])),
    )
    dashboard = [row for row in completed if int(row["dashboard_primary"]) == 1]
    expected: dict[str, object] = {
        "effective_state": "planned",
        "summary": None,
        "research_id": None,
        "page_url": None,
        "quick_links_json": "[]",
        "source_kind": "automatic",
        "source_event_id": None,
        "projection_version": "archive-status/v1",
    }
    if completed:
        expected["effective_state"] = "completed" if len(dashboard) == 1 else "conflicted"
        if len(dashboard) == 1:
            research_id = str(dashboard[0]["research_id"])
            active_row = active.get(research_id)
            metadata_rows = []
            if active_row is not None:
                metadata_rows = [
                    row
                    for row in _table_rows(actual, "derived_research_metadata").values()
                    if row["research_release_id"] == active_row["research_release_id"]
                    and row["derivation_type"] == "summary"
                    and row["status"] == "released"
                ]
            summary = None
            if metadata_rows:
                latest = max(
                    metadata_rows,
                    key=lambda row: (str(row["created_at"]), str(row["metadata_id"])),
                )
                value = _json_object(latest["payload_json"], label="research summary").get("summary")
                if isinstance(value, str) and value.strip():
                    summary = value.strip()
            if summary is None:
                expected["effective_state"] = "conflicted"
            else:
                expected.update(
                    {
                        "summary": summary,
                        "research_id": research_id,
                        "page_url": f"/research/{research_id}",
                        "quick_links_json": canonical_json(
                            [
                                {
                                    "research_id": str(row["research_id"]),
                                    "title": str(researches[str(row["research_id"])]["display_title"]),
                                    "page_url": f"/research/{row['research_id']}",
                                }
                                for row in completed
                                if str(row["research_id"]) != research_id
                            ]
                        ),
                    }
                )
        return expected
    states = [
        row
        for row in _table_rows(actual, "topic_state_event").values()
        if row["topic_id"] == topic_id
        and not any(
            later["supersedes_event_id"] == row["topic_state_event_id"]
            for later in _table_rows(actual, "topic_state_event").values()
        )
    ]
    if states:
        latest = max(
            states,
            key=lambda row: (str(row["occurred_at"]), str(row["topic_state_event_id"])),
        )
        expected.update(
            {
                "effective_state": latest["state"],
                "source_kind": "manual",
                "source_event_id": latest["topic_state_event_id"],
            }
        )
    return expected


def _validate_archive_receipt_actor(
    *,
    command: str,
    request: Mapping[str, object],
    receipt: Mapping[str, object],
    actors: Mapping[str, Mapping[str, object]],
) -> None:
    requested = request.get("actor")
    actor_id = receipt.get("actor_id")
    if requested is None:
        if (
            command not in {"research.complete", "research.revoke_completion"}
            or request.get("review_urn") is None
            or actor_id is not None
        ):
            raise RuntimeSealError("archive receipt has an invalid actorless request")
        return
    if not isinstance(requested, dict) or set(requested) != {
        "actor_kind",
        "display_name",
    }:
        raise RuntimeSealError("archive receipt request actor is invalid")
    try:
        canonical_actor = ActorInput.model_validate(requested).model_dump(mode="json")
    except (TypeError, ValueError) as error:
        raise RuntimeSealError("archive receipt request actor is invalid") from error
    if canonical_actor != requested:
        raise RuntimeSealError("archive receipt request actor is not canonical")
    actor = actors.get(str(actor_id)) if actor_id is not None else None
    kind = canonical_actor["actor_kind"]
    supplied_name = canonical_actor["display_name"]
    expected_name = {
        "zhang_zhengze": "张正泽",
        "song_dingkun": "宋定坤",
    }.get(kind)
    if expected_name is None and supplied_name is not None:
        expected_name = str(supplied_name).strip()
    if (
        actor is None
        or actor.get("actor_kind") != kind
        or actor.get("display_name") != expected_name
    ):
        raise RuntimeSealError("archive receipt actor differs from canonical request")


def _validate_archive_command_request(
    command: str, request: Mapping[str, object]
) -> None:
    """Validate the canonical public-service request before outcome replay."""

    if set(request) != ARCHIVE_COMMAND_REQUEST_FIELDS[command]:
        raise RuntimeSealError("archive command request field set is invalid")

    def require_text(name: str) -> str:
        value = request.get(name)
        if not isinstance(value, str) or not value:
            raise RuntimeSealError(f"archive command request {name} is invalid")
        return value

    def require_revision() -> None:
        value = request.get("expected_revision")
        if not isinstance(value, int) or isinstance(value, bool):
            raise RuntimeSealError("archive command expected revision is invalid")

    if command == "comment.create":
        require_text("research_id")
        body = request.get("body")
        if not isinstance(body, str) or body != body.strip():
            raise RuntimeSealError("archive comment request is not canonical")
    elif command in {"comment.update", "comment.delete"}:
        require_text("comment_id")
        require_revision()
        content = request.get("content")
        if command == "comment.delete":
            if content is not None:
                raise RuntimeSealError("archive comment deletion content must be null")
        elif not isinstance(content, str) or content != content.strip():
            raise RuntimeSealError("archive comment update is not canonical")
    elif command == "research_update.annotate":
        require_text("update_id")
        require_revision()
        revision = request.get("expected_revision")
        note = request.get("note")
        if (
            not isinstance(revision, int)
            or revision < 0
            or (
                note is not None
                and (
                    not isinstance(note, str)
                    or note != note.strip()
                    or not note
                    or len(note) > 500
                )
            )
        ):
            raise RuntimeSealError("research update annotation request is invalid")
    elif command == "topic.create_manual":
        topic = request.get("topic")
        if not isinstance(topic, dict) or set(topic) != {
            "title", "state", "note", "parent_topic_id", "manual_order"
        }:
            raise RuntimeSealError("manual topic request contract is invalid")
        try:
            canonical_topic = ManualTopicCreateInput.model_validate(topic).model_dump(
                mode="json"
            )
        except (TypeError, ValueError) as error:
            raise RuntimeSealError("manual topic request contract is invalid") from error
        if canonical_topic != topic:
            raise RuntimeSealError("manual topic request is not canonical")
        title = topic.get("title")
        note = topic.get("note")
        order = topic.get("manual_order")
        if (
            not isinstance(title, str)
            or title != title.strip()
            or not 1 <= len(title) <= 300
            or topic.get("state") not in {"planned", "paused"}
            or (note is not None and (
                not isinstance(note, str)
                or note != note.strip()
                or not 1 <= len(note) <= 2_000
            ))
            or (topic.get("parent_topic_id") is not None and not isinstance(topic.get("parent_topic_id"), str))
            or not isinstance(order, int)
            or isinstance(order, bool)
            or not 0 <= order <= 1_000_000
        ):
            raise RuntimeSealError("manual topic request value is invalid")
    elif command == "topic.update_manual":
        require_text("topic_id")
        require_revision()
        changes = request.get("changes")
        if not isinstance(changes, dict) or not changes or not set(changes).issubset(
            {"title", "state", "note", "parent_topic_id", "manual_order"}
        ):
            raise RuntimeSealError("manual topic changes contract is invalid")
        try:
            canonical_changes = ManualTopicUpdateInput.model_validate(changes).model_dump(
                mode="json", exclude_unset=True
            )
        except (TypeError, ValueError) as error:
            raise RuntimeSealError("manual topic changes contract is invalid") from error
        if canonical_changes != changes:
            raise RuntimeSealError("manual topic changes are not canonical")
        title = changes.get("title")
        note = changes.get("note")
        order = changes.get("manual_order")
        if (
            ("title" in changes and title is not None and (
                not isinstance(title, str)
                or title != title.strip()
                or not 1 <= len(title) <= 300
            ))
            or ("state" in changes and changes.get("state") not in {None, "planned", "paused"})
            or ("note" in changes and note is not None and (
                not isinstance(note, str)
                or note != note.strip()
                or not 1 <= len(note) <= 2_000
            ))
            or ("parent_topic_id" in changes and changes.get("parent_topic_id") is not None and not isinstance(changes.get("parent_topic_id"), str))
            or ("manual_order" in changes and order is not None and (
                not isinstance(order, int)
                or isinstance(order, bool)
                or not 0 <= order <= 1_000_000
            ))
        ):
            raise RuntimeSealError("manual topic changes value is invalid")
    elif command == "topic.retire_manual":
        require_text("topic_id")
        require_revision()
    elif command == "topic.create":
        topic = request.get("topic")
        if not isinstance(topic, dict) or set(topic) != {
            "topic_key", "title", "manual_order"
        }:
            raise RuntimeSealError("automatic topic request contract is invalid")
        try:
            canonical_topic = TopicInput.model_validate(topic).model_dump(mode="json")
        except (TypeError, ValueError) as error:
            raise RuntimeSealError("automatic topic request contract is invalid") from error
        if canonical_topic != topic:
            raise RuntimeSealError("automatic topic request is not canonical")
    elif command == "topic.link_research":
        require_text("topic_id")
        require_text("research_id")
        provenance = require_text("provenance_urn")
        dashboard = request.get("dashboard_primary")
        rank = request.get("display_rank")
        if (
            request.get("link_kind") not in {"primary", "supporting"}
            or not isinstance(dashboard, bool)
            or (dashboard and request.get("link_kind") != "primary")
            or not isinstance(rank, int)
            or isinstance(rank, bool)
            or rank < 0
            or provenance != provenance.strip()
        ):
            raise RuntimeSealError("topic research link request is invalid")
    elif command == "topic.set_state":
        require_text("topic_id")
        note = request.get("note")
        if (
            request.get("state") not in {"planned", "paused"}
            or (
                note is not None
                and (
                    not isinstance(note, str)
                    or not note
                    or note != note.strip()
                )
            )
        ):
            raise RuntimeSealError("topic state request is invalid")
    elif command == "research.set_work_state":
        require_text("research_id")
        note = request.get("note")
        if (
            request.get("state") not in {"planned", "in_progress", "paused"}
            or (
                note is not None
                and (
                    not isinstance(note, str)
                    or not note
                    or note != note.strip()
                )
            )
        ):
            raise RuntimeSealError("research work-state request is invalid")
    elif command in {"research.complete", "research.revoke_completion"}:
        require_text("research_id")
        reason = require_text("reason")
        actor = request.get("actor")
        review_urn = request.get("review_urn")
        if (
            reason != reason.strip()
            or (actor is None) == (review_urn is None)
            or (review_urn is not None and (
                not isinstance(review_urn, str) or not review_urn.strip()
            ))
        ):
            raise RuntimeSealError("research decision request mode is invalid")
        require_text(
            "research_release_id"
            if command == "research.complete"
            else "target_decision_id"
        )


def _validate_applied_archive_identity(
    *,
    command: str,
    request: Mapping[str, object],
    data: Mapping[str, object],
    aggregate: str,
    actor: Mapping[str, object] | None,
) -> None:
    exact_fields: dict[str, set[str]] = {
        "comment.create": {
            "comment_id", "research_id", "actor", "content", "created_at",
            "updated_at", "revision", "request",
        },
        "comment.update": {
            "comment_id", "revision", "deleted", "updated_at", "deleted_at",
            "request", "content",
        },
        "comment.delete": {
            "comment_id", "revision", "deleted", "updated_at", "deleted_at",
            "request",
        },
        "research_update.annotate": {
            "update_id", "annotation_event_id", "actor", "note", "revision",
            "occurred_at",
        },
        "topic.create_manual": TOPIC_MANAGEMENT_RESULT_FIELDS | {"state_event_id"},
        "topic.update_manual": TOPIC_MANAGEMENT_RESULT_FIELDS,
        "topic.retire_manual": TOPIC_MANAGEMENT_RESULT_FIELDS,
        "topic.create": {"topic_id", "topic_key", "title", "manual_order", "revision"},
        "topic.link_research": {
            "topic_id", "research_id", "link_kind", "dashboard_primary",
            "display_rank", "provenance_urn", "status", "projection_updated_at",
        },
        "topic.set_state": {"topic_id", "state", "note", "event_id", "revision"},
        "research.set_work_state": {"research_id", "state", "note", "event_id"},
        "research.revoke_completion": {
            "decision_id", "research_id", "target_decision_id", "decision",
        },
    }
    expected_fields = exact_fields.get(command)
    if command == "research.complete":
        expected_fields = {
            "decision_id", "research_id", "research_release_id", "decision"
        }
        if data.get("decision_kind") == "reviewed_import":
            expected_fields |= {"decision_kind", "review_certificate_urn"}
    if expected_fields is None or set(data) != expected_fields:
        raise RuntimeSealError("archive applied result field set is invalid")

    def require_equal(*fields: str) -> None:
        if any(data.get(field) != request.get(field) for field in fields):
            raise RuntimeSealError("archive applied result identity differs from request")

    if command.startswith("comment."):
        content = request.get("body" if command == "comment.create" else "content")
        if command != "comment.delete" and (
            not isinstance(content, str) or not content or len(content) > 8_000
        ):
            raise RuntimeSealError("applied archive comment content is invalid")
        if command == "comment.create" and (
            actor is None
            or not isinstance(data.get("actor"), dict)
            or data["actor"] != {
                "actor_kind": actor.get("actor_kind"),
                "display_name": actor.get("display_name"),
            }
        ):
            raise RuntimeSealError("created comment actor differs from canonical actor")

    if command == "research_update.annotate":
        update_id = str(request.get("update_id", ""))
        if (
            not update_id
            or data.get("update_id") != update_id
            or data.get("note") != request.get("note")
            or not isinstance(data.get("annotation_event_id"), str)
            or not str(data["annotation_event_id"])
            or not isinstance(data.get("revision"), int)
            or int(data["revision"]) != int(request.get("expected_revision", -1)) + 1
            or not isinstance(data.get("occurred_at"), str)
            or not str(data["occurred_at"])
            or actor is None
            or data.get("actor") != {
                "actor_kind": actor.get("actor_kind"),
                "display_name": actor.get("display_name"),
            }
            or aggregate != f"qrh:research-update:{update_id}"
        ):
            raise RuntimeSealError(
                "research update annotation result differs from request"
            )

    if command == "topic.create_manual":
        topic = request.get("topic")
        if not isinstance(topic, dict) or set(topic) != {
            "title", "state", "note", "parent_topic_id", "manual_order"
        }:
            raise RuntimeSealError("manual topic request is invalid")
        expected = {
            "title": topic.get("title"),
            "parent_topic_id": topic.get("parent_topic_id"),
            "manual_order": topic.get("manual_order"),
            "manual_state": topic.get("state"),
            "state_note": topic.get("note"),
        }
        topic_id = str(data.get("topic_id", ""))
        if not topic_id or aggregate != f"qrh:topic:{topic_id}" or any(
            data.get(field) != value for field, value in expected.items()
        ):
            raise RuntimeSealError("manual topic result/aggregate differs from request")
    elif command == "topic.update_manual":
        require_equal("topic_id")
        changes = request.get("changes")
        if not isinstance(changes, dict) or not changes or not set(changes).issubset(
            {"title", "state", "note", "parent_topic_id", "manual_order"}
        ):
            raise RuntimeSealError("manual topic changes are invalid")
        projection_names = {"state": "manual_state", "note": "state_note"}
        if any(
            data.get(projection_names.get(field, field)) != value
            for field, value in changes.items()
        ):
            raise RuntimeSealError("manual topic result differs from requested changes")
        if aggregate != f"qrh:topic:{request.get('topic_id')}":
            raise RuntimeSealError("manual topic aggregate differs from request")
    elif command == "topic.retire_manual":
        require_equal("topic_id")
        if aggregate != f"qrh:topic:{request.get('topic_id')}":
            raise RuntimeSealError("retired topic aggregate differs from request")
    elif command == "topic.create":
        topic = request.get("topic")
        topic_id = str(data.get("topic_id", ""))
        if (
            not isinstance(topic, dict)
            or set(topic) != {"topic_key", "title", "manual_order"}
            or not topic_id
            or aggregate != f"qrh:topic:{topic_id}"
            or any(data.get(field) != value for field, value in topic.items())
        ):
            raise RuntimeSealError("created topic result/aggregate differs from request")
    elif command == "topic.link_research":
        require_equal(
            "topic_id",
            "research_id",
            "link_kind",
            "dashboard_primary",
            "display_rank",
            "provenance_urn",
        )
        if aggregate != f"qrh:topic:{request.get('topic_id')}":
            raise RuntimeSealError("topic link aggregate differs from request")
    elif command == "topic.set_state":
        require_equal("topic_id", "state", "note")
        if aggregate != f"qrh:topic:{request.get('topic_id')}":
            raise RuntimeSealError("topic state aggregate differs from request")
    elif command == "research.set_work_state":
        require_equal("research_id", "state", "note")
        if aggregate != f"qrh:research:{request.get('research_id')}":
            raise RuntimeSealError("research state aggregate differs from request")
    elif command == "research.complete":
        require_equal("research_id", "research_release_id")
        if (
            (request.get("actor") is None) == (request.get("review_urn") is None)
            or data.get("decision") != "completed"
            or aggregate != f"qrh:research:{request.get('research_id')}"
        ):
            raise RuntimeSealError("research completion result differs from request")
    elif command == "research.revoke_completion":
        require_equal("research_id", "target_decision_id")
        if (
            request.get("actor") is None
            or request.get("review_urn") is not None
            or data.get("decision") != "revoked"
            or aggregate != f"qrh:research:{request.get('research_id')}"
        ):
            raise RuntimeSealError("research revocation result differs from request")


def _review_certificate_matches_candidate(
    certificate: Mapping[str, object] | None,
    *,
    certificate_urn: object,
    identity: Mapping[str, object],
) -> bool:
    """Replay ``ReviewAuthority.verify_certificate`` from sealed row material."""

    if certificate is None or not isinstance(certificate_urn, str):
        return False
    try:
        spec = ReviewCertificateSpec(
            gate_name=str(certificate["gate_name"]),
            gate_version=str(certificate["gate_version"]),
            subject_urn=str(certificate["subject_urn"]),
            subject_version_urn=str(certificate["subject_version_urn"]),
            artifact_manifest_hash=str(certificate["artifact_manifest_hash"]),
            requirements_manifest_hash=str(
                certificate["requirements_manifest_hash"]
            ),
            review_artifact_hash=str(certificate["review_artifact_hash"]),
            review_set_hash=str(certificate["review_set_hash"]),
            reviewer_identity_hash=str(certificate["reviewer_identity_hash"]),
        )
        expected_hash = review_certificate_material_hash(
            spec,
            str(certificate["issuance_key"]),
            str(certificate["issued_at"]),
        )
        certificate_id = str(certificate["certificate_id"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        certificate.get("certificate_urn") == certificate_urn
        and certificate_urn == f"qrh:review-certificate:{certificate_id}"
        and certificate.get("certificate_hash") == expected_hash
        and certificate.get("verdict") == "pass"
        and spec.gate_name == "archive_research_completion"
        and spec.gate_version == "1"
        and spec.subject_urn == identity.get("subject_urn")
        and spec.subject_version_urn == identity.get("subject_version_urn")
        and spec.artifact_manifest_hash == identity.get("artifact_manifest_hash")
        and spec.requirements_manifest_hash
        == ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH
    )


def _validate_rejected_archive_receipt(
    *,
    command: str,
    request: Mapping[str, object],
    receipt: Mapping[str, object],
    error: Mapping[str, object],
    topics: Mapping[str, Mapping[str, object]],
    researches: Mapping[str, Mapping[str, object]],
    active_releases: Mapping[str, Mapping[str, object]],
    decisions: Mapping[str, Mapping[str, object]],
    completion_consumptions: set[str],
    candidate_identities: Mapping[tuple[str, str], Mapping[str, object]],
    released_summary_ids: set[str],
    review_certificates: Mapping[str, Mapping[str, object]],
    comments: Mapping[str, Mapping[str, object]],
    comment_events: list[Mapping[str, object]],
    topic_mutations: list[Mapping[str, object]],
    topic_states: list[Mapping[str, object]],
    topic_links: list[Mapping[str, object]],
    research_updates: Mapping[str, Mapping[str, object]] | None = None,
    research_update_annotations: tuple[Mapping[str, object], ...] = (),
) -> None:
    code = str(error.get("code", ""))
    expected_status = ARCHIVE_REJECTION_STATUS[command].get(code)
    if expected_status is None or int(receipt["http_status"]) != expected_status:
        raise RuntimeSealError("archive rejected command code/status is unreachable")
    aggregate = str(receipt["aggregate_urn"])
    topic_id = str(request.get("topic_id", ""))
    research_id = str(request.get("research_id", ""))
    if command == "comment.create":
        expected_aggregate = f"qrh:research:{research_id}"
    elif command in {"comment.update", "comment.delete"}:
        expected_aggregate = f"qrh:comment:{request.get('comment_id')}"
    elif command == "research_update.annotate":
        expected_aggregate = f"qrh:research-update:{request.get('update_id')}"
    elif command == "topic.create_manual":
        if not aggregate.startswith("qrh:topic:") or aggregate[10:] in topics:
            raise RuntimeSealError("rejected manual topic aggregate is not an unused identity")
        expected_aggregate = aggregate
    elif command == "topic.create":
        topic = request.get("topic")
        topic_key = topic.get("topic_key") if isinstance(topic, dict) else None
        matching = [
            row
            for row in topics.values()
            if row["topic_key"] == topic_key
            and str(row["created_at"]) <= str(receipt["created_at"])
        ]
        if code != "topic_key_conflict" or len(matching) != 1:
            raise RuntimeSealError("rejected topic conflict has no existing target")
        expected_aggregate = f"qrh:topic:{matching[0]['topic_id']}"
    elif command.startswith("topic."):
        expected_aggregate = f"qrh:topic:{topic_id}"
    else:
        expected_aggregate = f"qrh:research:{research_id}"
    if aggregate != expected_aggregate:
        raise RuntimeSealError("archive rejected command aggregate differs from request")

    receipt_time = str(receipt["created_at"])
    def comment_state(comment_id: str) -> tuple[bool, bool, int | None]:
        events = sorted(
            (
                row
                for row in comment_events
                if row["comment_id"] == comment_id
                and str(row["occurred_at"]) <= receipt_time
            ),
            key=lambda row: (int(row["revision"]), str(row["comment_event_id"])),
        )
        if events:
            latest = events[-1]
            return True, latest["event_type"] == "delete", int(latest["revision"])
        row = comments.get(comment_id)
        if row is None or str(row["created_at"]) > receipt_time:
            return False, False, None
        deleted = row.get("deleted_at") is not None and str(row["deleted_at"]) <= receipt_time
        return True, deleted, int(row["revision"])

    def topic_state(target_id: str) -> tuple[Mapping[str, object] | None, int | None]:
        row = topics.get(target_id)
        if row is None or str(row["created_at"]) > receipt_time:
            return None, None
        past = sorted(
            (
                item
                for item in topic_mutations
                if item["topic_id"] == target_id
                and str(item["occurred_at"]) <= receipt_time
            ),
            key=lambda item: int(item["new_revision"]),
        )
        if past:
            latest = past[-1]
            return (
                _json_object(latest["new_payload_json"], label="topic temporal snapshot"),
                int(latest["new_revision"]),
            )
        future = sorted(
            (
                item
                for item in topic_mutations
                if item["topic_id"] == target_id
                and str(item["occurred_at"]) > receipt_time
                and item["old_payload_json"] is not None
            ),
            key=lambda item: int(item["new_revision"]),
        )
        if future:
            first = future[0]
            return (
                _json_object(first["old_payload_json"], label="topic temporal snapshot"),
                int(first["prior_revision"]),
            )
        return (
            {
                "title": row["title"],
                "parent_topic_id": row["parent_topic_id"],
                "manual_order": row["manual_order"],
                "retired_at": row["retired_at"],
            },
            int(row["revision"]),
        )

    def parent_is_invalid(subject_id: str, parent_id: object) -> bool:
        if parent_id is None:
            return False
        parent_snapshot, _revision = topic_state(str(parent_id))
        has_child = any(
            child_id != subject_id
            and (state := topic_state(child_id))[0] is not None
            and state[0].get("parent_topic_id") == subject_id
            for child_id in topics
        )
        return (
            str(parent_id) == subject_id
            or parent_snapshot is None
            or parent_snapshot.get("retired_at") is not None
            or parent_snapshot.get("parent_topic_id") is not None
            or has_child
        )

    def has_active_topic_state(target_id: str) -> bool:
        return any(
            row["topic_id"] == target_id
            and str(row["occurred_at"]) <= receipt_time
            and not any(
                later["supersedes_event_id"] == row["topic_state_event_id"]
                and str(later["occurred_at"]) <= receipt_time
                for later in topic_states
            )
            for row in topic_states
        )

    def valid_completion_exists(target_research: str, release_id: object) -> bool:
        candidates = [
            row
            for row in decisions.values()
            if row["research_id"] == target_research
            and row["research_release_id"] == release_id
            and row["decision"] == "completed"
            and str(row["decided_at"]) <= receipt_time
            and (
                row["decision_kind"] == "human"
                or str(row["decision_id"]) in completion_consumptions
            )
        ]
        return any(
            not any(
                later["target_decision_id"] == row["decision_id"]
                or later["supersedes_decision_id"] == row["decision_id"]
                for later in decisions.values()
                if str(later["decided_at"]) <= receipt_time
            )
            for row in candidates
        )

    topic = topics.get(topic_id)
    topic_snapshot, topic_revision = topic_state(topic_id)
    research = researches.get(research_id)
    update_rows = research_updates or {}
    derived_code: str | None = None
    if command == "comment.create":
        body = request.get("body")
        if not isinstance(body, str) or not body or len(body) > 8_000:
            derived_code = "invalid_comment"
        elif research is None:
            derived_code = "research_not_found"
    elif command in {"comment.update", "comment.delete"}:
        target = str(request.get("comment_id", ""))
        exists, deleted, revision = comment_state(target)
        if not exists or deleted:
            derived_code = "comment_not_found"
        elif revision != int(request.get("expected_revision", -1)):
            derived_code = "revision_conflict"
        elif command == "comment.update":
            content = request.get("content")
            if not isinstance(content, str) or not content or len(content) > 8_000:
                derived_code = "invalid_comment"
    elif command == "research_update.annotate":
        target = str(request.get("update_id", ""))
        update = update_rows.get(target)
        note = request.get("note")
        expected_revision = int(request.get("expected_revision", -1))
        latest_revision = max(
            (
                int(row["revision"])
                for row in research_update_annotations
                if row["update_id"] == target
                and str(row["occurred_at"]) <= receipt_time
            ),
            default=0,
        )
        if update is None or str(update["activated_at"]) > receipt_time:
            derived_code = "research_update_not_found"
        elif expected_revision < 0 or (
            note is not None
            and (
                not isinstance(note, str)
                or note != note.strip()
                or not note
                or len(note) > 500
            )
        ):
            derived_code = "invalid_research_update_annotation"
        elif latest_revision != expected_revision:
            derived_code = "revision_conflict"
    elif command == "topic.create_manual":
        requested_topic = request.get("topic")
        if not isinstance(requested_topic, dict) or set(requested_topic) != {
            "title", "state", "note", "parent_topic_id", "manual_order"
        }:
            raise RuntimeSealError("manual topic request contract is invalid")
        if parent_is_invalid(aggregate.removeprefix("qrh:topic:"), requested_topic.get("parent_topic_id")):
            derived_code = "invalid_topic_parent"
    elif command == "topic.update_manual":
        changes = request.get("changes")
        if not isinstance(changes, dict) or not changes or not set(changes).issubset(
            {"title", "state", "note", "parent_topic_id", "manual_order"}
        ):
            raise RuntimeSealError("manual topic changes contract is invalid")
        if topic_snapshot is None or topic_snapshot.get("retired_at") is not None:
            derived_code = "topic_not_found"
        elif topic is None or topic.get("created_by_actor_id") is None:
            derived_code = "topic_not_manual"
        elif topic_revision != int(request.get("expected_revision", -1)):
            derived_code = "revision_conflict"
        elif not has_active_topic_state(topic_id):
            derived_code = "manual_topic_state_missing"
        elif any(
            field in changes and changes[field] is None
            for field in ("title", "state", "manual_order")
        ):
            derived_code = "invalid_topic_update"
        else:
            parent_id = changes.get("parent_topic_id", topic_snapshot.get("parent_topic_id"))
            if parent_is_invalid(topic_id, parent_id):
                derived_code = "invalid_topic_parent"
    elif command == "topic.retire_manual":
        if topic_snapshot is None:
            derived_code = "topic_not_found"
        elif topic_snapshot.get("retired_at") is not None:
            derived_code = "topic_already_retired"
        elif topic is None or topic.get("created_by_actor_id") is None:
            derived_code = "topic_not_manual"
        elif topic_revision != int(request.get("expected_revision", -1)):
            derived_code = "revision_conflict"
        elif any(
            child_id != topic_id
            and (state := topic_state(child_id))[0] is not None
            and state[0].get("retired_at") is None
            and state[0].get("parent_topic_id") == topic_id
            for child_id in topics
        ):
            derived_code = "topic_has_active_children"
        elif any(
            row["topic_id"] == topic_id
            and row["status"] == "active"
            and str(row["created_at"]) <= receipt_time
            for row in topic_links
        ):
            derived_code = "topic_has_active_research_links"
    elif command == "topic.create":
        requested_topic = request.get("topic")
        if not isinstance(requested_topic, dict) or set(requested_topic) != {
            "topic_key", "title", "manual_order"
        }:
            raise RuntimeSealError("automatic topic request contract is invalid")
        if any(
            row["topic_key"] == requested_topic.get("topic_key")
            and str(row["created_at"]) <= receipt_time
            for row in topics.values()
        ):
            derived_code = "topic_key_conflict"
    elif command == "topic.link_research":
        if topic_snapshot is None or research is None:
            derived_code = "topic_or_research_not_found"
    elif command == "topic.set_state":
        if topic_snapshot is None:
            derived_code = "topic_not_found"
    elif command == "research.set_work_state":
        if research is None:
            derived_code = "research_not_found"
    elif command == "research.complete":
        active = active_releases.get(research_id)
        release_id = request.get("research_release_id")
        if active is None or active["research_release_id"] != release_id:
            derived_code = "release_not_active"
        elif valid_completion_exists(research_id, release_id):
            derived_code = "already_completed"
        elif request.get("review_urn") is not None:
            identity = candidate_identities.get((str(release_id), research_id))
            if identity is None or str(release_id) not in released_summary_ids:
                derived_code = "review_candidate_incomplete"
            else:
                review_urn = request.get("review_urn")
                certificate = review_certificates.get(str(review_urn))
                if not _review_certificate_matches_candidate(
                    certificate,
                    certificate_urn=review_urn,
                    identity=identity,
                ):
                    derived_code = "review_certificate_invalid"
    elif command == "research.revoke_completion":
        target_id = str(request.get("target_decision_id", ""))
        target = decisions.get(target_id)
        if request.get("review_urn") is not None:
            derived_code = "review_certificate_required"
        elif (
            target is None
            or target["research_id"] != research_id
            or target["decision"] != "completed"
            or str(target["decided_at"]) > receipt_time
        ):
            derived_code = "completion_not_found"
        elif any(
            row["target_decision_id"] == target_id
            and str(row["decided_at"]) <= receipt_time
            for row in decisions.values()
        ):
            derived_code = "completion_already_revoked"
    if derived_code != code:
        raise RuntimeSealError(
            "archive rejected command is not reachable from its recorded preconditions"
        )
    return


def _research_update_export_material(
    actual: Mapping[str, object],
) -> tuple[str, str, int]:
    researches = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "research").values()
    }
    identities = {
        (str(row["research_release_id"]), str(row["research_id"])): row
        for row in _table_rows(
            actual, "research_release_candidate_identity"
        ).values()
    }
    actors = {
        str(row["actor_id"]): row for row in _table_rows(actual, "actor").values()
    }
    annotation_rows = sorted(
        _table_rows(actual, "research_update_annotation_event").values(),
        key=lambda row: (
            str(row["update_id"]),
            int(row["revision"]),
            str(row["annotation_event_id"]),
        ),
    )
    annotations: dict[str, list[dict[str, object]]] = {}
    for row in annotation_rows:
        actor = actors.get(str(row["actor_id"]))
        if actor is None:
            raise RuntimeSealError("research update annotation actor is missing")
        annotations.setdefault(str(row["update_id"]), []).append(
            {
                "annotation_event_id": str(row["annotation_event_id"]),
                "actor": {
                    "actor_kind": str(actor["actor_kind"]),
                    "display_name": str(actor["display_name"]),
                },
                "idempotency_key": str(row["idempotency_key"]),
                "note": None if row["note"] is None else str(row["note"]),
                "revision": int(row["revision"]),
                "occurred_at": str(row["occurred_at"]),
            }
        )
    update_rows = sorted(
        _table_rows(actual, "research_update").values(),
        key=lambda row: (str(row["activated_at"]), str(row["update_id"])),
        reverse=True,
    )
    records: list[dict[str, object]] = []
    for row in update_rows:
        research_id = str(row["research_id"])
        research = researches.get(research_id)
        if research is None:
            raise RuntimeSealError("research update research is missing")
        identity = identities.get(
            (str(row["research_release_id"]), research_id)
        )
        records.append(
            {
                "schema_version": "archive-research-update-history/v1",
                "update_id": str(row["update_id"]),
                "research_id": research_id,
                "canonical_slug": str(research["canonical_slug"]),
                "activation_id": str(row["activation_id"]),
                "research_release_id": str(row["research_release_id"]),
                "release_key": (
                    None if identity is None else str(identity["release_key"])
                ),
                "content_revision_id": str(row["content_revision_id"]),
                "event_kind": str(row["event_kind"]),
                "release_revision": int(row["release_revision"]),
                "title_snapshot": str(row["title_snapshot"]),
                "activated_at": str(row["activated_at"]),
                "created_at": str(row["created_at"]),
                "annotation_events": annotations.get(str(row["update_id"]), []),
            }
        )
    canonical_records = canonical_json(records)
    watermark = stable_sha256(
        "archive-research-update-watermark/v1", canonical_records
    )
    payload = b"".join(
        (canonical_json(record) + "\n").encode("utf-8") for record in records
    )
    return watermark, hashlib.sha256(payload).hexdigest(), len(records)


def _validate_research_update_projection(actual: Mapping[str, object]) -> None:
    """Rebuild D-05 from activation chains and reject any silent drift."""

    researches = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "research").values()
    }
    releases = {
        (str(row["research_id"]), str(row["research_release_id"])): row
        for row in _table_rows(actual, "research_release").values()
    }
    active = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "active_research_release").values()
    }
    grouped: dict[str, list[dict[str, object]]] = {}
    for row in _table_rows(actual, "research_release_activation").values():
        grouped.setdefault(str(row["research_id"]), []).append(row)

    expected_updates: dict[str, dict[str, object]] = {}
    for research_id, activation_rows in grouped.items():
        research = researches.get(research_id)
        if research is None:
            raise RuntimeSealError("research update activation has no research")
        by_id = {str(row["activation_id"]): row for row in activation_rows}
        roots = [
            row
            for row in activation_rows
            if row["supersedes_activation_id"] is None
        ]
        if len(roots) != 1:
            raise RuntimeSealError("research update activation chain has no unique root")
        successors: dict[str, dict[str, object]] = {}
        for row in activation_rows:
            predecessor = row["supersedes_activation_id"]
            if predecessor is None:
                continue
            predecessor_id = str(predecessor)
            if predecessor_id not in by_id or predecessor_id in successors:
                raise RuntimeSealError(
                    "research update activation chain branches or disconnects"
                )
            successors[predecessor_id] = row
        chain: list[dict[str, object]] = []
        seen: set[str] = set()
        current = roots[0]
        while True:
            current_id = str(current["activation_id"])
            if current_id in seen:
                raise RuntimeSealError("research update activation chain cycles")
            seen.add(current_id)
            chain.append(current)
            following = successors.get(current_id)
            if following is None:
                break
            current = following
        if len(chain) != len(activation_rows):
            raise RuntimeSealError("research update activation chain is disconnected")
        active_row = active.get(research_id)
        if (
            active_row is None
            or str(active_row["activation_id"])
            != str(chain[-1]["activation_id"])
            or str(active_row["research_release_id"])
            != str(chain[-1]["research_release_id"])
            or int(active_row["revision"]) != len(chain)
        ):
            raise RuntimeSealError("active release does not close its update chain")

        first_by_content: dict[str, tuple[int, dict[str, object]]] = {}
        for revision, activation in enumerate(chain, start=1):
            release = releases.get(
                (research_id, str(activation["research_release_id"]))
            )
            if release is None:
                raise RuntimeSealError("research update activation has no release")
            content_revision_id = str(release["document_manifest_hash"])
            first_by_content.setdefault(content_revision_id, (revision, activation))
        for content_revision_id, (revision, activation) in first_by_content.items():
            update_id = stable_sha256(research_id, content_revision_id, "published")
            activated_at = str(activation["activated_at"])
            expected_updates[update_id] = {
                "update_id": update_id,
                "research_id": research_id,
                "activation_id": str(activation["activation_id"]),
                "research_release_id": str(activation["research_release_id"]),
                "content_revision_id": content_revision_id,
                "event_kind": "published",
                "release_revision": revision,
                "title_snapshot": str(research["display_title"]),
                "activated_at": activated_at,
                "created_at": activated_at,
            }

    if set(active) != set(grouped):
        raise RuntimeSealError("active release and update activation sets differ")
    actual_updates = {
        str(row["update_id"]): row
        for row in _table_rows(actual, "research_update").values()
    }
    if set(actual_updates) != set(expected_updates):
        raise RuntimeSealError(
            "research update set is not the exact activation projection"
        )
    for update_id, expected in expected_updates.items():
        row = actual_updates[update_id]
        observed = {
            field: int(row[field]) if field == "release_revision" else str(row[field])
            for field in expected
        }
        if observed != expected:
            raise RuntimeSealError(
                "research update row differs from its first activation occurrence"
            )

    recorded_events = [
        row
        for row in _table_rows(actual, "outbox_event").values()
        if row["event_type"] == "ArchiveResearchUpdateRecorded"
    ]
    if len(recorded_events) != len(expected_updates):
        raise RuntimeSealError(
            "research update facts do not have exactly one outbox event"
        )
    seen_event_updates: set[str] = set()
    for row in recorded_events:
        payload = _json_object(
            str(row["payload_json"]), label="research update recorded outbox"
        )
        update_id = str(payload.get("update_id", ""))
        expected = expected_updates.get(update_id)
        if expected is None or update_id in seen_event_updates:
            raise RuntimeSealError("research update recorded outbox identity is invalid")
        seen_event_updates.add(update_id)
        expected_payload = {
            field: expected[field]
            for field in (
                "update_id",
                "research_id",
                "research_release_id",
                "activation_id",
                "content_revision_id",
                "event_kind",
                "release_revision",
                "title_snapshot",
                "activated_at",
            )
        }
        payload_json = canonical_json(expected_payload)
        if (
            payload != expected_payload
            or str(row["event_version"]) != "1"
            or str(row["aggregate_urn"])
            != f"qrh:research-update:{update_id}"
            or str(row["payload_json"]) != payload_json
            or str(row["payload_hash"])
            != stable_sha256("archive-outbox/v1", payload_json)
            or str(row["created_at"]) != expected["activated_at"]
        ):
            raise RuntimeSealError(
                "research update recorded outbox is not event-bound"
            )


def _validate_archive_closure(
    baseline: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    platform_actual: Mapping[str, object],
    delivery: Path | None = None,
) -> None:
    additions = _compare_database_baseline(
        baseline,
        actual,
        append_tables=ARCHIVE_APPEND_TABLES,
        mutable_tables=ARCHIVE_MUTABLE_TABLES,
        label="archive runtime",
    )
    _validate_research_update_projection(actual)
    actors_by_id = {
        str(row["actor_id"]): row
        for row in _table_rows(actual, "actor").values()
    }
    topics_by_id = {
        str(row["topic_id"]): row
        for row in _table_rows(actual, "topic").values()
    }
    researches_by_id = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "research").values()
    }
    active_releases_by_research = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "active_research_release").values()
    }
    all_decisions_by_id = {
        str(row["decision_id"]): row
        for row in _table_rows(actual, "research_completion_decision").values()
    }
    completion_consumption_ids = {
        str(row["decision_id"])
        for row in _table_rows(
            actual, "research_completion_review_consumption"
        ).values()
    }
    candidate_identities = {
        (str(row["research_release_id"]), str(row["research_id"])): row
        for row in _table_rows(
            actual, "research_release_candidate_identity"
        ).values()
    }
    released_summary_ids = {
        str(row["research_release_id"])
        for row in _table_rows(actual, "derived_research_metadata").values()
        if row["research_release_id"] is not None
        and row["derivation_type"] == "summary"
        and row["status"] == "released"
    }
    review_certificates = {
        str(row["certificate_urn"]): row
        for row in _table_rows(platform_actual, "review_certificate").values()
    }
    comments_by_id = {
        str(row["comment_id"]): row
        for row in _table_rows(actual, "comment").values()
    }
    research_updates_by_id = {
        str(row["update_id"]): row
        for row in _table_rows(actual, "research_update").values()
    }
    all_research_update_annotations = tuple(
        _table_rows(actual, "research_update_annotation_event").values()
    )
    all_comment_events_for_receipts = list(
        _table_rows(actual, "comment_event").values()
    )
    all_topic_mutations_for_receipts = list(
        _table_rows(actual, "topic_mutation_event").values()
    )
    all_topic_states_for_receipts = list(
        _table_rows(actual, "topic_state_event").values()
    )
    all_topic_links_for_receipts = list(
        _table_rows(actual, "topic_research_link").values()
    )
    receipts = _new_rows(baseline, actual, "command_receipt")
    comment_events = _new_rows(baseline, actual, "comment_event")
    research_update_annotation_events = _new_rows(
        baseline, actual, "research_update_annotation_event"
    )
    work_state_events = _new_rows(baseline, actual, "research_work_state_event")
    topic_state_events = _new_rows(baseline, actual, "topic_state_event")
    topic_mutations = _new_rows(baseline, actual, "topic_mutation_event")
    outbox_events = _new_rows(baseline, actual, "outbox_event")
    applied_comment: dict[tuple[str, int], tuple[dict[str, object], dict[str, object]]] = {}
    applied_update_annotations: dict[
        tuple[str, int], tuple[dict[str, object], dict[str, object]]
    ] = {}
    applied_topic: dict[tuple[str, int], tuple[dict[str, object], dict[str, object]]] = {}
    no_op_topic_receipts: list[tuple[dict[str, object], dict[str, object]]] = []
    topic_receipt_candidates: dict[
        tuple[str, int], list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    applied_research: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    applied_links: dict[
        tuple[str, str], list[tuple[dict[str, object], dict[str, object]]]
    ] = {}
    applied_decisions: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    expected_outbox: set[tuple[str, str, str]] = set()
    expected_outbox_created_at: dict[tuple[str, str, str], str] = {}
    referenced_actors: set[str] = set()
    new_topic_mutation_ids = {
        (str(row["topic_id"]), int(row["new_revision"]))
        for row in topic_mutations
    }
    for receipt in receipts:
        command = str(receipt["command_name"])
        if command not in ARCHIVE_ALLOWED_COMMANDS:
            raise RuntimeSealError(f"archive command is not resume-allowlisted: {command}")
        result_json = str(receipt["result_json"])
        if receipt["result_hash"] != stable_sha256(
            "archive-command-result/v1", result_json
        ):
            raise RuntimeSealError("archive command result hash is invalid")
        result = _json_object(result_json, label="archive command result")
        request = result.get("request")
        if (
            not isinstance(request, dict)
            or receipt["payload_hash"]
            != stable_sha256(
                "archive-command/v1", command, canonical_json(request)
            )
        ):
            raise RuntimeSealError("archive command request/payload hash is invalid")
        _validate_archive_command_request(command, request)
        _validate_archive_receipt_actor(
            command=command,
            request=request,
            receipt=receipt,
            actors=actors_by_id,
        )
        if receipt.get("actor_id") is not None:
            referenced_actors.add(str(receipt["actor_id"]))
        if receipt["outcome"] != "applied":
            error = result.get("error")
            if (
                set(result) != {"error", "request"}
                or not isinstance(error, dict)
                or set(error) != {"code", "message"}
                or not isinstance(error.get("code"), str)
                or not str(error["code"]).strip()
                or not isinstance(error.get("message"), str)
                or not str(error["message"]).strip()
                or not 400 <= int(receipt["http_status"]) < 500
            ):
                raise RuntimeSealError("rejected archive command result is invalid")
            _validate_rejected_archive_receipt(
                command=command,
                request=request,
                receipt=receipt,
                error=error,
                topics=topics_by_id,
                researches=researches_by_id,
                active_releases=active_releases_by_research,
                decisions=all_decisions_by_id,
                completion_consumptions=completion_consumption_ids,
                candidate_identities=candidate_identities,
                released_summary_ids=released_summary_ids,
                review_certificates=review_certificates,
                comments=comments_by_id,
                comment_events=all_comment_events_for_receipts,
                topic_mutations=all_topic_mutations_for_receipts,
                topic_states=all_topic_states_for_receipts,
                topic_links=all_topic_links_for_receipts,
                research_updates=research_updates_by_id,
                research_update_annotations=all_research_update_annotations,
            )
            continue
        if int(receipt["http_status"]) != ARCHIVE_APPLIED_STATUS[command]:
            raise RuntimeSealError("applied archive command HTTP status is invalid")
        if set(result) != {"data", "request"}:
            raise RuntimeSealError("applied archive command result field set is invalid")
        data = result.get("data")
        if not isinstance(data, dict):
            raise RuntimeSealError("applied archive receipt has no result data")
        aggregate = str(receipt["aggregate_urn"])
        _validate_applied_archive_identity(
            command=command,
            request=request,
            data=data,
            aggregate=aggregate,
            actor=(
                actors_by_id.get(str(receipt["actor_id"]))
                if receipt.get("actor_id") is not None
                else None
            ),
        )
        payload = canonical_json(data)
        if command.startswith("comment."):
            comment_id = str(data.get("comment_id", ""))
            revision = int(data.get("revision", 0))
            identity = (comment_id, revision)
            if (
                aggregate != f"qrh:comment:{comment_id}"
                or revision < 1
                or identity in applied_comment
            ):
                raise RuntimeSealError("comment receipt aggregate/revision is invalid")
            request = data.get("request")
            if request != result.get("request"):
                raise RuntimeSealError("comment data/request binding differs")
            applied_comment[identity] = (receipt, data)
            event_type = {
                "comment.create": "ArchiveCommentCreated",
                "comment.update": "ArchiveCommentUpdated",
                "comment.delete": "ArchiveCommentDeleted",
            }[command]
        elif command == "research_update.annotate":
            update_id = str(data.get("update_id", ""))
            revision = int(data.get("revision", 0))
            identity = (update_id, revision)
            if (
                update_id not in research_updates_by_id
                or aggregate != f"qrh:research-update:{update_id}"
                or revision < 1
                or identity in applied_update_annotations
            ):
                raise RuntimeSealError(
                    "research update annotation receipt identity is invalid"
                )
            applied_update_annotations[identity] = (receipt, data)
            event_type = "ArchiveResearchUpdateAnnotated"
        elif command == "topic.link_research":
            topic_id = str(data.get("topic_id", ""))
            research_id = str(data.get("research_id", ""))
            identity = (topic_id, research_id)
            if aggregate != f"qrh:topic:{topic_id}" or not topic_id or not research_id:
                raise RuntimeSealError("topic link receipt identity is invalid")
            applied_links.setdefault(identity, []).append((receipt, data))
            event_type = "ArchiveTopicResearchLinked"
        elif command.startswith("topic."):
            topic_id = str(data.get("topic_id", ""))
            revision = int(data.get("revision", 0))
            if aggregate != f"qrh:topic:{topic_id}" or revision < 1:
                raise RuntimeSealError("topic receipt aggregate/revision is invalid")
            identity = (topic_id, revision)
            topic_receipt_candidates.setdefault(identity, []).append((receipt, data))
            continue
        elif command == "research.set_work_state":
            research_id = str(data.get("research_id", ""))
            event_id = str(data.get("event_id", ""))
            if aggregate != f"qrh:research:{research_id}" or not event_id:
                raise RuntimeSealError("research state receipt aggregate/event is invalid")
            if event_id in applied_research:
                raise RuntimeSealError("research state event has duplicate receipts")
            applied_research[event_id] = (receipt, data)
            event_type = "ArchiveResearchWorkStateSet"
        else:
            research_id = str(data.get("research_id", ""))
            decision_id = str(data.get("decision_id", ""))
            if aggregate != f"qrh:research:{research_id}" or not decision_id:
                raise RuntimeSealError("research decision receipt identity is invalid")
            if decision_id in applied_decisions:
                raise RuntimeSealError("research decision has duplicate receipts")
            applied_decisions[decision_id] = (receipt, data)
            event_type = (
                "ArchiveResearchCompleted"
                if command == "research.complete"
                else "ArchiveResearchCompletionRevoked"
            )
        outbox_identity = (event_type, aggregate, payload)
        expected_outbox.add(outbox_identity)
        if command == "research_update.annotate":
            occurred_at = data.get("occurred_at")
            if not isinstance(occurred_at, str) or not occurred_at:
                raise RuntimeSealError(
                    "research update annotation result has no event timestamp"
                )
            expected_outbox_created_at[outbox_identity] = occurred_at

    mutation_by_identity = {
        (str(row["topic_id"]), int(row["new_revision"])): row
        for row in topic_mutations
    }
    command_by_mutation_kind = {
        "update": "topic.update_manual",
        "retire": "topic.retire_manual",
        "state": "topic.set_state",
    }
    outbox_by_command = {
        "topic.create_manual": "ArchiveManualTopicCreated",
        "topic.update_manual": "ArchiveManualTopicUpdated",
        "topic.retire_manual": "ArchiveManualTopicRetired",
        "topic.set_state": "ArchiveTopicStateSet",
        "topic.create": "ArchiveTopicCreated",
    }
    for identity, candidates in topic_receipt_candidates.items():
        mutation = mutation_by_identity.get(identity)
        if mutation is None:
            if any(row[0]["command_name"] != "topic.update_manual" for row in candidates):
                raise RuntimeSealError("applied topic receipt has no mutation")
            no_op_topic_receipts.extend(candidates)
            continue
        mutation_kind = str(mutation["event_kind"])
        if mutation_kind == "create":
            snapshot = _json_object(
                mutation["new_payload_json"], label="created topic snapshot"
            )
            expected_command = (
                "topic.create"
                if snapshot.get("manual_state") is None
                else "topic.create_manual"
            )
        else:
            expected_command = command_by_mutation_kind[mutation_kind]
        matching = [row for row in candidates if row[0]["command_name"] == expected_command]
        if not matching:
            raise RuntimeSealError("topic mutation has no matching applied receipt")
        # 一个 revision 只能由一条 mutation 推进；同 revision 之后的合法 no-op
        # update receipt 不产生 mutation/outbox，以 created_at 次序区分。
        matching.sort(key=lambda row: (str(row[0]["created_at"]), str(row[0]["receipt_id"])))
        bound = matching[0]
        applied_topic[identity] = bound
        extras = [row for row in candidates if row is not bound]
        if any(row[0]["command_name"] != "topic.update_manual" for row in extras):
            raise RuntimeSealError("topic mutation has duplicate applied receipts")
        no_op_topic_receipts.extend(extras)
        receipt, data = bound
        aggregate = str(receipt["aggregate_urn"])
        expected_outbox.add(
            (outbox_by_command[expected_command], aggregate, canonical_json(data))
        )

    seen_comment: set[tuple[str, int]] = set()
    for event in comment_events:
        identity = (str(event["comment_id"]), int(event["revision"]))
        if identity in seen_comment:
            raise RuntimeSealError("comment event identity is duplicated")
        bound = applied_comment.get(identity)
        if bound is None:
            raise RuntimeSealError("comment event has no applied command receipt")
        expected_kind = {
            "comment.create": "create",
            "comment.update": "update",
            "comment.delete": "delete",
        }[str(bound[0]["command_name"])]
        receipt, data = bound
        request = data.get("request")
        assert isinstance(request, dict)
        if event["event_type"] != expected_kind or event["actor_id"] != receipt["actor_id"]:
            raise RuntimeSealError("comment event differs from its command receipt")
        occurred_at = str(event["occurred_at"])
        if data.get("updated_at") != occurred_at:
            raise RuntimeSealError("comment result timestamp differs from its event")
        if expected_kind == "create":
            expected_request_keys = {"research_id", "actor", "body"}
            content = request.get("body")
            if (
                set(request) != expected_request_keys
                or int(event["revision"]) != 1
                or event["old_body_hash"] is not None
                or event["new_body_hash"]
                != hashlib.sha256(str(content).encode("utf-8")).hexdigest()
                or data.get("research_id") != request.get("research_id")
                or data.get("content") != content
                or data.get("created_at") != occurred_at
                or data.get("revision") != 1
            ):
                raise RuntimeSealError("created comment differs from its request/event")
        else:
            expected_request_keys = {
                "comment_id",
                "actor",
                "content",
                "expected_revision",
            }
            if (
                set(request) != expected_request_keys
                or request.get("comment_id") != identity[0]
                or int(request.get("expected_revision", -1)) + 1 != identity[1]
                or bool(data.get("deleted")) != (expected_kind == "delete")
                or data.get("deleted_at")
                != (occurred_at if expected_kind == "delete" else None)
                or (
                    expected_kind == "update"
                    and (
                        data.get("content") != request.get("content")
                        or event["new_body_hash"]
                        != hashlib.sha256(
                            str(request.get("content")).encode("utf-8")
                        ).hexdigest()
                    )
                )
                or (expected_kind == "delete" and event["new_body_hash"] is not None)
            ):
                raise RuntimeSealError("changed comment differs from its request/event")
        seen_comment.add(identity)
        referenced_actors.add(str(event["actor_id"]))
    if seen_comment != set(applied_comment):
        raise RuntimeSealError("applied comment receipt has no unique event")

    seen_work_events: set[str] = set()
    all_work_rows = _table_rows(actual, "research_work_state_event")
    for event in work_state_events:
        event_id = str(event["work_state_event_id"])
        bound = applied_research.get(event_id)
        if bound is None:
            raise RuntimeSealError("research work event has no applied command receipt")
        receipt, data = bound
        if (
            event["research_id"] != data.get("research_id")
            or event["state"] != data.get("state")
            or event["note"] != data.get("note")
            or event["actor_id"] != receipt["actor_id"]
        ):
            raise RuntimeSealError("research work event differs from its command receipt")
        predecessors = [
            row
            for row in all_work_rows.values()
            if row["research_id"] == event["research_id"]
            and row["work_state_event_id"] != event_id
            and (str(row["occurred_at"]), str(row["work_state_event_id"]))
            < (str(event["occurred_at"]), event_id)
        ]
        expected_predecessor = (
            max(
                predecessors,
                key=lambda row: (
                    str(row["occurred_at"]), str(row["work_state_event_id"])
                ),
            )["work_state_event_id"]
            if predecessors
            else None
        )
        if event["supersedes_event_id"] != expected_predecessor:
            raise RuntimeSealError("research work state supersedes chain is discontinuous")
        seen_work_events.add(event_id)
        referenced_actors.add(str(event["actor_id"]))
    if seen_work_events != set(applied_research):
        raise RuntimeSealError("applied research state receipt has no unique event")

    decision_rows = _new_rows(baseline, actual, "research_completion_decision")
    consumption_rows = _new_rows(
        baseline, actual, "research_completion_review_consumption"
    )
    seen_decisions: set[str] = set()
    for decision in decision_rows:
        decision_id = str(decision["decision_id"])
        bound = applied_decisions.get(decision_id)
        if bound is None:
            raise RuntimeSealError("research decision has no applied command receipt")
        receipt, data = bound
        command = str(receipt["command_name"])
        result = _json_object(receipt["result_json"], label="research decision result")
        request = result.get("request")
        if not isinstance(request, dict):
            raise RuntimeSealError("research decision receipt omits canonical request")
        expected_decision = "completed" if command == "research.complete" else "revoked"
        if (
            decision["research_id"] != data.get("research_id")
            or decision["research_id"] != request.get("research_id")
            or decision["decision"] != expected_decision
            or data.get("decision") != expected_decision
            or decision["actor_id"] != receipt["actor_id"]
            or decision["reason"] != request.get("reason")
            or decision["supersedes_decision_id"] is not None
            or str(decision["decided_at"]) > str(receipt["created_at"])
        ):
            raise RuntimeSealError("research decision differs from its receipt")
        if expected_decision == "completed":
            reviewed = request.get("review_urn") is not None
            if (
                decision["research_release_id"] != data.get("research_release_id")
                or decision["research_release_id"] != request.get("research_release_id")
                or decision["target_decision_id"] is not None
                or decision["decision_kind"]
                != ("reviewed_import" if reviewed else "human")
                or decision["review_urn"]
                != (request.get("review_urn") if reviewed else None)
                or (reviewed and (
                    receipt["actor_id"] is not None
                    or data.get("decision_kind") != "reviewed_import"
                    or data.get("review_certificate_urn") != request.get("review_urn")
                ))
            ):
                raise RuntimeSealError("completion decision release binding is invalid")
        else:
            target = all_decisions_by_id.get(str(request.get("target_decision_id", "")))
            if (
                request.get("actor") is None
                or request.get("review_urn") is not None
                or decision["decision_kind"] != "human"
                or decision["review_urn"] is not None
                or decision["target_decision_id"] != data.get("target_decision_id")
                or decision["target_decision_id"] != request.get("target_decision_id")
                or target is None
                or target.get("research_id") != decision["research_id"]
                or target.get("decision") != "completed"
                or target.get("research_release_id") != decision["research_release_id"]
                or str(target.get("decided_at", "")) > str(decision["decided_at"])
            ):
                raise RuntimeSealError("revocation target binding is invalid")
        seen_decisions.add(decision_id)
    if seen_decisions != set(applied_decisions):
        raise RuntimeSealError("applied research decision receipt has no unique row")
    consumption_by_decision = {
        str(row["decision_id"]): row for row in consumption_rows
    }
    for decision in decision_rows:
        decision_id = str(decision["decision_id"])
        consumption = consumption_by_decision.get(decision_id)
        if decision["decision_kind"] == "reviewed_import":
            receipt, data = applied_decisions[decision_id]
            result = _json_object(receipt["result_json"], label="reviewed decision result")
            request = result.get("request")
            identity = candidate_identities.get(
                (str(decision["research_release_id"]), str(decision["research_id"]))
            )
            if (
                not isinstance(request, dict)
                or consumption is None
                or identity is None
                or str(decision["research_release_id"]) not in released_summary_ids
                or consumption["research_id"] != decision["research_id"]
                or consumption["research_release_id"] != decision["research_release_id"]
                or consumption["certificate_urn"]
                != request.get("review_urn")
                or consumption["certificate_urn"] != decision["review_urn"]
                or consumption["certificate_urn"] != data.get("review_certificate_urn")
                or consumption["subject_urn"] != identity["subject_urn"]
                or consumption["subject_version_urn"] != identity["subject_version_urn"]
                or consumption["artifact_manifest_hash"] != identity["artifact_manifest_hash"]
                or consumption["requirements_manifest_hash"]
                != ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH
                or consumption["consumed_at"] != decision["decided_at"]
            ):
                raise RuntimeSealError("reviewed completion consumption is incomplete")
            certificate = review_certificates.get(str(consumption["certificate_urn"]))
            if (
                not _review_certificate_matches_candidate(
                    certificate,
                    certificate_urn=consumption["certificate_urn"],
                    identity=identity,
                )
                or certificate is None
                or consumption["certificate_hash"]
                != certificate.get("certificate_hash")
            ):
                raise RuntimeSealError(
                    "reviewed completion certificate binding is invalid"
                )
        elif consumption is not None:
            raise RuntimeSealError("human decision cannot consume a review certificate")
    if not set(consumption_by_decision).issubset(seen_decisions):
        raise RuntimeSealError("orphan completion review consumption")

    seen_topic: set[tuple[str, int]] = set()
    for event in topic_mutations:
        identity = (str(event["topic_id"]), int(event["new_revision"]))
        bound = applied_topic.get(identity)
        if bound is None:
            raise RuntimeSealError("topic mutation has no applied command receipt")
        expected_kind = {
            "topic.create_manual": "create",
            "topic.update_manual": "update",
            "topic.retire_manual": "retire",
            "topic.set_state": "state",
            "topic.create": "create",
        }[str(bound[0]["command_name"])]
        bound_result = _json_object(
            bound[0]["result_json"], label="topic mutation command result"
        )
        bound_request = bound_result.get("request")
        if not isinstance(bound_request, dict):
            raise RuntimeSealError("topic mutation receipt omits canonical request")
        bound_command = str(bound[0]["command_name"])
        if bound_command in {"topic.update_manual", "topic.retire_manual"} and (
            int(bound_request.get("expected_revision", -1))
            != int(event["prior_revision"])
            or int(event["new_revision"]) != int(event["prior_revision"]) + 1
        ):
            raise RuntimeSealError(
                "topic mutation prior revision differs from command precondition"
            )
        if event["event_kind"] != expected_kind or event["actor_id"] != bound[0]["actor_id"]:
            raise RuntimeSealError("topic mutation differs from its command receipt")
        seen_topic.add(identity)
        referenced_actors.add(str(event["actor_id"]))
    if seen_topic != set(applied_topic):
        raise RuntimeSealError("applied topic receipt has no unique mutation event")

    state_events_by_mutation: dict[tuple[str, int], list[dict[str, object]]] = {
        identity: [] for identity in applied_topic
    }
    for event in topic_state_events:
        candidates = [
            identity
            for identity, mutation in mutation_by_identity.items()
            if identity[0] == str(event["topic_id"])
            and mutation["actor_id"] == event["actor_id"]
            and mutation["occurred_at"] == event["occurred_at"]
        ]
        if len(candidates) != 1:
            raise RuntimeSealError("topic state event has no unique applied mutation")
        state_events_by_mutation[candidates[0]].append(event)
        referenced_actors.add(str(event["actor_id"]))
    all_state_rows = _table_rows(actual, "topic_state_event")
    for identity, (command_receipt, command_data) in applied_topic.items():
        mutation = mutation_by_identity[identity]
        command = str(command_receipt["command_name"])
        bound_events = state_events_by_mutation[identity]
        if command == "topic.create_manual":
            if (
                len(bound_events) != 1
                or bound_events[0]["supersedes_event_id"] is not None
                or command_data.get("state_event_id")
                != bound_events[0]["topic_state_event_id"]
            ):
                raise RuntimeSealError("created manual topic requires one root state event")
        elif command == "topic.create":
            if bound_events:
                raise RuntimeSealError("automatic topic creation cannot append a state event")
        elif command == "topic.retire_manual":
            if bound_events:
                raise RuntimeSealError("retiring a manual topic cannot append state events")
        elif command == "topic.set_state":
            if (
                len(bound_events) != 1
                or command_data.get("event_id")
                != bound_events[0]["topic_state_event_id"]
            ):
                raise RuntimeSealError("topic.set_state requires one state event")
        elif len(bound_events) > 1:
            raise RuntimeSealError("manual topic update appended multiple state events")
        old_snapshot = (
            _json_object(mutation["old_payload_json"], label="old topic snapshot")
            if mutation["old_payload_json"] is not None
            else None
        )
        new_snapshot = _json_object(
            mutation["new_payload_json"], label="new topic snapshot"
        )
        state_changed = old_snapshot is None or (
            old_snapshot.get("manual_state") != new_snapshot.get("manual_state")
            or old_snapshot.get("state_note") != new_snapshot.get("state_note")
        )
        if command == "topic.update_manual" and state_changed != bool(bound_events):
            raise RuntimeSealError("manual topic state change/event cardinality differs")
        if bound_events:
            event = bound_events[0]
            if (
                event["state"] != new_snapshot.get("manual_state")
                or event["note"] != new_snapshot.get("state_note")
                or event["actor_id"] != command_receipt["actor_id"]
            ):
                raise RuntimeSealError("topic state event differs from mutation snapshot")
            if command in {"topic.update_manual", "topic.set_state"}:
                predecessors = [
                    row
                    for row in all_state_rows.values()
                    if row["topic_id"] == identity[0]
                    and row["topic_state_event_id"] != event["topic_state_event_id"]
                    and (
                        str(row["occurred_at"]), str(row["topic_state_event_id"])
                    )
                    < (
                        str(event["occurred_at"]), str(event["topic_state_event_id"])
                    )
                ]
                if not predecessors and command == "topic.update_manual":
                    raise RuntimeSealError("topic update state event has no predecessor")
                predecessor_id = (
                    max(
                        predecessors,
                        key=lambda row: (
                            str(row["occurred_at"]), str(row["topic_state_event_id"])
                        ),
                    )["topic_state_event_id"]
                    if predecessors
                    else None
                )
                if event["supersedes_event_id"] != predecessor_id:
                    raise RuntimeSealError("topic state supersedes chain is discontinuous")

    seen_update_annotations: set[tuple[str, int]] = set()
    for event in research_update_annotation_events:
        identity = (str(event["update_id"]), int(event["revision"]))
        bound = applied_update_annotations.get(identity)
        if bound is None:
            raise RuntimeSealError(
                "research update annotation event has no applied command receipt"
            )
        receipt, data = bound
        if (
            identity in seen_update_annotations
            or event["annotation_event_id"] != data.get("annotation_event_id")
            or event["actor_id"] != receipt.get("actor_id")
            or event["idempotency_key"] != receipt.get("idempotency_key")
            or event["note"] != data.get("note")
            or event["occurred_at"] != data.get("occurred_at")
            or int(event["revision"])
            != int(data.get("revision", 0))
        ):
            raise RuntimeSealError(
                "research update annotation event differs from command closure"
            )
        prior = [
            row
            for row in all_research_update_annotations
            if row["update_id"] == event["update_id"]
            and int(row["revision"]) < int(event["revision"])
        ]
        expected_prior_revision = max(
            (int(row["revision"]) for row in prior), default=0
        )
        request_payload = json.loads(str(receipt["result_json"])).get("request")
        if (
            not isinstance(request_payload, dict)
            or int(request_payload.get("expected_revision", -1))
            != expected_prior_revision
            or int(event["revision"]) != expected_prior_revision + 1
        ):
            raise RuntimeSealError(
                "research update annotation revision chain is discontinuous"
            )
        seen_update_annotations.add(identity)
    if seen_update_annotations != set(applied_update_annotations):
        raise RuntimeSealError(
            "applied research update annotation has no append-only event"
        )

    actual_outbox = {
        (str(row["event_type"]), str(row["aggregate_urn"]), str(row["payload_json"]))
        for row in outbox_events
    }
    if len(actual_outbox) != len(outbox_events):
        raise RuntimeSealError("archive outbox contains a duplicate command event")
    if actual_outbox != expected_outbox:
        raise RuntimeSealError("archive outbox does not close over applied commands")
    for row in outbox_events:
        payload_json = str(row["payload_json"])
        outbox_identity = (
            str(row["event_type"]),
            str(row["aggregate_urn"]),
            payload_json,
        )
        if str(row["event_version"]) != "1":
            raise RuntimeSealError("archive outbox event version is not allowlisted")
        expected_created_at = expected_outbox_created_at.get(outbox_identity)
        if expected_created_at is not None and str(row["created_at"]) != expected_created_at:
            raise RuntimeSealError(
                "research update annotation outbox timestamp differs from its event"
            )
        if row["payload_hash"] != stable_sha256("archive-outbox/v1", payload_json):
            raise RuntimeSealError("archive outbox payload hash is invalid")

    actors = _table_rows(actual, "actor")
    for key in additions.get("actor", set()):
        actor = actors[key]
        if str(actor["actor_id"]) not in referenced_actors:
            raise RuntimeSealError("new actor is not referenced by a command/event closure")

    comments = _table_rows(actual, "comment")
    actor_rows_by_id = {
        str(row["actor_id"]): row for row in _table_rows(actual, "actor").values()
    }
    all_comment_events = _table_rows(actual, "comment_event")
    baseline_comments = _rows_by_key(baseline["comment"])  # type: ignore[index]
    for key, comment in comments.items():
        changed = key not in baseline_comments or (
            baseline_comments[key].get("row_sha256")
            != _rows_by_key(actual["comment"])[key].get("row_sha256")  # type: ignore[index]
        )
        if not changed:
            continue
        identity = (str(comment["comment_id"]), int(comment["revision"]))
        if identity not in applied_comment:
            raise RuntimeSealError("changed comment is not closed by its latest receipt")
        events = sorted(
            (
                event
                for event in all_comment_events.values()
                if event["comment_id"] == comment["comment_id"]
            ),
            key=lambda row: int(row["revision"]),
        )
        latest = events[-1]
        if int(latest["revision"]) != int(comment["revision"]):
            raise RuntimeSealError("comment projection revision is not the latest event")
        new_events = [event for event in events if (str(event["comment_id"]), int(event["revision"])) in applied_comment]
        first_revision = int(new_events[0]["revision"])
        baseline_row = (
            _row_dict(baseline["comment"], baseline_comments[key])  # type: ignore[index]
            if key in baseline_comments
            else None
        )
        expected_previous_hash = (
            hashlib.sha256(str(baseline_row["body"]).encode("utf-8")).hexdigest()
            if baseline_row is not None
            else None
        )
        expected_revision = int(baseline_row["revision"]) + 1 if baseline_row else 1
        for event in new_events:
            event_identity = (str(event["comment_id"]), int(event["revision"]))
            receipt, data = applied_comment[event_identity]
            request = data["request"]
            assert isinstance(request, dict)
            actor = actor_rows_by_id.get(str(receipt["actor_id"]))
            request_actor = request.get("actor")
            if not isinstance(request_actor, dict) or actor is None:
                raise RuntimeSealError("comment command actor is incomplete")
            requested_name = request_actor.get("display_name")
            if (
                actor["actor_kind"] != request_actor.get("actor_kind")
                or (
                    requested_name is not None
                    and str(actor["display_name"]) != str(requested_name).strip()
                )
                or int(event["revision"]) != expected_revision
                or event["old_body_hash"] != expected_previous_hash
            ):
                raise RuntimeSealError("comment event hash/revision chain is discontinuous")
            expected_previous_hash = event["new_body_hash"]
            expected_revision += 1
        if first_revision != (int(baseline_row["revision"]) + 1 if baseline_row else 1):
            raise RuntimeSealError("comment event sequence does not extend activation")
        latest_receipt, latest_data = applied_comment[identity]
        create_data = applied_comment[(identity[0], 1)][1] if baseline_row is None else None
        expected_body = (
            str(latest_data["content"])
            if latest["event_type"] == "update"
            else (
                str(create_data["content"])
                if baseline_row is None
                else str(baseline_row["body"])
            )
        )
        if latest["event_type"] == "delete":
            prior_content_events = [
                applied_comment[(identity[0], int(event["revision"]))][1]
                for event in new_events
                if event["event_type"] in {"create", "update"}
            ]
            if prior_content_events:
                expected_body = str(prior_content_events[-1]["content"])
        expected_created_at = (
            create_data["created_at"] if create_data is not None else baseline_row["created_at"]
        )
        expected_research = (
            create_data["research_id"] if create_data is not None else baseline_row["research_id"]
        )
        expected_actor = (
            applied_comment[(identity[0], 1)][0]["actor_id"]
            if baseline_row is None
            else baseline_row["actor_id"]
        )
        if (
            comment["body"] != expected_body
            or comment["research_id"] != expected_research
            or comment["actor_id"] != expected_actor
            or comment["created_at"] != expected_created_at
            or comment["updated_at"] != latest["occurred_at"]
            or comment["deleted_at"]
            != (latest["occurred_at"] if latest["event_type"] == "delete" else None)
        ):
            raise RuntimeSealError("comment row is not the exact latest event projection")

    topics = _table_rows(actual, "topic")
    projections = _table_rows(actual, "topic_projection")
    baseline_projection_rows = _rows_by_key(baseline["topic_projection"])  # type: ignore[index]
    all_mutations = _table_rows(actual, "topic_mutation_event")
    all_states = _table_rows(actual, "topic_state_event")
    changed_topic_ids = {topic_id for topic_id, _revision in applied_topic}
    projection_command_topic_ids = {
        topic_id
        for (topic_id, _revision), (receipt, _data) in applied_topic.items()
        if receipt["command_name"] != "topic.retire_manual"
    }
    links = _table_rows(actual, "topic_research_link")
    baseline_link_rows = _rows_by_key(baseline["topic_research_link"])  # type: ignore[index]
    actual_link_rows = _rows_by_key(actual["topic_research_link"])  # type: ignore[index]
    changed_links = {
        (
            str(_row_dict(actual["topic_research_link"], row)["topic_id"]),  # type: ignore[index]
            str(_row_dict(actual["topic_research_link"], row)["research_id"]),  # type: ignore[index]
        )
        for key, row in actual_link_rows.items()
        if key not in baseline_link_rows
        or row.get("row_sha256") != baseline_link_rows[key].get("row_sha256")
    }
    if not changed_links.issubset(set(applied_links)):
        raise RuntimeSealError("topic research links do not close over applied commands")
    for identity, commands in applied_links.items():
        commands.sort(
            key=lambda item: (
                str(item[1].get("projection_updated_at", "")),
                str(item[0]["receipt_id"]),
            )
        )
        _receipt, data = commands[-1]
        link = next(
            (
                row
                for row in links.values()
                if (str(row["topic_id"]), str(row["research_id"])) == identity
            ),
            None,
        )
        if link is None or any(
            link[field] != data.get(field)
            for field in (
                "topic_id",
                "research_id",
                "link_kind",
                "dashboard_primary",
                "display_rank",
                "provenance_urn",
                "status",
            )
        ):
            raise RuntimeSealError("topic research link differs from its receipt/event")
        for _command_receipt, command_data in commands:
            projection_time = str(command_data.get("projection_updated_at", ""))
            matching_outbox = [
                row
                for row in outbox_events
                if row["event_type"] == "ArchiveTopicResearchLinked"
                and row["aggregate_urn"] == f"qrh:topic:{identity[0]}"
                and row["payload_json"] == canonical_json(command_data)
            ]
            if (
                not projection_time
                or len(matching_outbox) != 1
                or matching_outbox[0]["created_at"] != projection_time
            ):
                raise RuntimeSealError("topic link projection timestamp is not event-bound")
        link_key = canonical_json([identity[0], identity[1]])
        first_projection_time = str(commands[0][1]["projection_updated_at"])
        if link_key not in baseline_link_rows and link["created_at"] != first_projection_time:
            raise RuntimeSealError("new topic link timestamp differs from its event")
    for receipt, data in no_op_topic_receipts:
        topic_id = str(data["topic_id"])
        topic = next((row for row in topics.values() if row["topic_id"] == topic_id), None)
        receipt_result = _json_object(
            receipt["result_json"], label="no-op topic command result"
        )
        request = receipt_result.get("request")
        if not isinstance(request, dict):
            raise RuntimeSealError("no-op topic receipt omits canonical request")
        mutations_at_receipt = [
            row
            for row in all_mutations.values()
            if row["topic_id"] == topic_id
            and str(row["occurred_at"]) <= str(receipt["created_at"])
        ]
        states = [
            row for row in _table_rows(actual, "topic_state_event").values()
            if row["topic_id"] == topic_id
            and str(row["occurred_at"]) <= str(receipt["created_at"])
        ]
        if topic is None or not mutations_at_receipt or not states:
            raise RuntimeSealError("no-op topic receipt targets an incomplete topic")
        latest_mutation = max(
            mutations_at_receipt, key=lambda row: int(row["new_revision"])
        )
        snapshot = _json_object(
            latest_mutation["new_payload_json"], label="no-op topic snapshot"
        )
        latest_state = max(
            states,
            key=lambda row: (str(row["occurred_at"]), str(row["topic_state_event_id"])),
        )
        expected = {
            "topic_id": topic_id,
            "topic_key": topic["topic_key"],
            "title": snapshot["title"],
            "parent_topic_id": snapshot["parent_topic_id"],
            "manual_order": snapshot["manual_order"],
            "revision": latest_mutation["new_revision"],
            "retired_at": snapshot["retired_at"],
            "manual_state": latest_state["state"],
            "state_note": latest_state["note"],
        }
        if any(data.get(key) != value for key, value in expected.items()):
            raise RuntimeSealError("no-op topic receipt differs from receipt-time projection")
        if int(request.get("expected_revision", -1)) != int(data["revision"]):
            raise RuntimeSealError("no-op topic expected revision differs from projection")
        if receipt["aggregate_urn"] != f"qrh:topic:{topic_id}":
            raise RuntimeSealError("no-op topic receipt aggregate is invalid")

    research_projections = _table_rows(actual, "research_status_projection")
    baseline_research_rows = _rows_by_key(baseline["research_status_projection"])  # type: ignore[index]
    actual_research_rows = _rows_by_key(actual["research_status_projection"])  # type: ignore[index]
    changed_research_projection_ids = {
        str(
            _row_dict(
                actual["research_status_projection"], actual_research_rows[key]  # type: ignore[index]
            )["research_id"]
        )
        for key in actual_research_rows
        if key not in baseline_research_rows
        or baseline_research_rows[key].get("row_sha256")
        != actual_research_rows[key].get("row_sha256")
    }
    applied_research_ids = {
        str(data["research_id"]) for _receipt, data in applied_research.values()
    } | {
        str(data["research_id"]) for _receipt, data in applied_decisions.values()
    }
    research_command_times: dict[str, list[str]] = {}
    for event in work_state_events:
        research_command_times.setdefault(str(event["research_id"]), []).append(
            str(event["occurred_at"])
        )
    for decision in decision_rows:
        research_command_times.setdefault(str(decision["research_id"]), []).append(
            str(decision["decided_at"])
        )
    if not changed_research_projection_ids.issubset(applied_research_ids):
        raise RuntimeSealError("research projection changed without a state/decision command")
    active_releases = {
        str(row["research_id"]): row
        for row in _table_rows(actual, "active_research_release").values()
    }
    all_decisions = _table_rows(actual, "research_completion_decision")
    all_consumptions = {
        str(row["decision_id"]): row
        for row in _table_rows(
            actual, "research_completion_review_consumption"
        ).values()
    }
    baseline_projection_ids = {
        str(
            _row_dict(
                baseline["research_status_projection"], row  # type: ignore[index]
            )["research_id"]
        )
        for row in baseline_research_rows.values()
    }
    for research_id in changed_research_projection_ids:
        projection = next(
            (
                row
                for row in research_projections.values()
                if row["research_id"] == research_id
            ),
            None,
        )
        if projection is None:
            raise RuntimeSealError("research work-state projection is missing")
        active = active_releases.get(research_id)
        release_id = str(active["research_release_id"]) if active else None
        candidates = [
            row
            for row in all_decisions.values()
            if row["research_id"] == research_id
            and row["research_release_id"] == release_id
            and row["decision"] == "completed"
            and not any(
                later["target_decision_id"] == row["decision_id"]
                or later["supersedes_decision_id"] == row["decision_id"]
                for later in all_decisions.values()
            )
            and (
                row["decision_kind"] == "human"
                or str(row["decision_id"]) in all_consumptions
            )
        ]
        completion = (
            max(
                candidates,
                key=lambda row: (str(row["decided_at"]), str(row["decision_id"])),
            )
            if candidates
            else None
        )
        if completion is not None:
            expected_work = "completed"
            expected_work_event = None
            expected_completion = completion["decision_id"]
        else:
            work_candidates = [
                row
                for row in all_work_rows.values()
                if row["research_id"] == research_id
                and not any(
                    later["supersedes_event_id"] == row["work_state_event_id"]
                    for later in all_work_rows.values()
                )
            ]
            latest_work = (
                max(
                    work_candidates,
                    key=lambda row: (
                        str(row["occurred_at"]), str(row["work_state_event_id"])
                    ),
                )
                if work_candidates
                else None
            )
            expected_work = latest_work["state"] if latest_work else "planned"
            expected_work_event = latest_work["work_state_event_id"] if latest_work else None
            expected_completion = None
        if (
            projection["work_status"] != expected_work
            or projection["work_source_event_id"] != expected_work_event
            or projection["completion_decision_id"] != expected_completion
        ):
            raise RuntimeSealError("research work-state projection is not deterministic")
        expected_release = "published" if active is not None else "unpublished"
        expected_activation = active["activation_id"] if active is not None else None
        if (
            projection["release_status"] != expected_release
            or projection["release_activation_id"] != expected_activation
            or projection["projection_version"] != "archive-status/v1"
            or projection["updated_at"] != max(research_command_times[research_id])
        ):
            raise RuntimeSealError("research release/work projection is inconsistent")
        if research_id not in baseline_projection_ids and (
            projection["evidence_status"] != "unknown"
            or projection["evidence_source_urn"] is not None
        ):
            raise RuntimeSealError("new research work projection contains unrelated state")
    for topic_id in changed_topic_ids:
        topic = next((row for row in topics.values() if row["topic_id"] == topic_id), None)
        projection = next(
            (row for row in projections.values() if row["topic_id"] == topic_id), None
        )
        if topic is None or projection is None:
            raise RuntimeSealError("topic closure is incomplete")
        latest_mutation = max(
            (row for row in all_mutations.values() if row["topic_id"] == topic_id),
            key=lambda row: int(row["new_revision"]),
        )
        if int(latest_mutation["new_revision"]) != int(topic["revision"]):
            raise RuntimeSealError("topic row is not the latest mutation projection")
        topic_states = [
            row for row in all_states.values() if row["topic_id"] == topic_id
        ]
        latest_state = (
            max(
                topic_states,
                key=lambda row: (
                    str(row["occurred_at"]), str(row["topic_state_event_id"])
                ),
            )
            if topic_states
            else None
        )
        snapshot = _json_object(
            latest_mutation["new_payload_json"], label="topic mutation snapshot"
        )
        expected_snapshot = {
            "title": topic["title"],
            "parent_topic_id": topic["parent_topic_id"],
            "manual_order": topic["manual_order"],
            "manual_state": latest_state["state"] if latest_state else None,
            "state_note": latest_state["note"] if latest_state else None,
            "retired_at": topic["retired_at"],
        }
        if snapshot != expected_snapshot:
            raise RuntimeSealError("topic row differs from its mutation snapshot")

    projection_additions = additions.get("topic_projection", set())
    projection_rows = _rows_by_key(actual["topic_projection"])  # type: ignore[index]
    changed_projection_ids = {
        str(_row_dict(actual["topic_projection"], projection_rows[key])["topic_id"])  # type: ignore[index]
        for key in projection_rows
        if key in projection_additions
        or baseline_projection_rows[key].get("row_sha256")
        != projection_rows[key].get("row_sha256")
    }
    links = _table_rows(actual, "topic_research_link")
    linked_topic_ids = {
        str(row["topic_id"])
        for row in links.values()
        if row["status"] == "active" and str(row["research_id"]) in applied_research_ids
    } | {topic_id for topic_id, _research_id in applied_links}
    if not changed_projection_ids.issubset(
        projection_command_topic_ids | linked_topic_ids
    ):
        raise RuntimeSealError("topic projection changed without a topic command")
    for topic_id in changed_projection_ids:
        key = canonical_json([topic_id])
        projection = _row_dict(actual["topic_projection"], projection_rows[key])  # type: ignore[index]
        expected = _expected_topic_projection(topic_id, actual)
        if any(projection.get(column) != value for column, value in expected.items()):
            raise RuntimeSealError("topic projection is not a deterministic event replay")
        command_times = [
            str(row["occurred_at"])
            for row in topic_mutations
            if str(row["topic_id"]) == topic_id
        ]
        command_times.extend(
            str(data.get("projection_updated_at", ""))
            for (linked_topic, _research_id), commands in applied_links.items()
            if linked_topic == topic_id
            for _receipt, data in commands
        )
        command_times.extend(
            timestamp
            for row in links.values()
            if str(row["topic_id"]) == topic_id and row["status"] == "active"
            for timestamp in research_command_times.get(str(row["research_id"]), [])
        )
        if not command_times or "" in command_times:
            raise RuntimeSealError("topic projection has no exact command timestamp")
        if projection["updated_at"] != max(command_times):
            raise RuntimeSealError("topic projection timestamp is not an exact replay")

    update_event_types = {
        "ArchiveResearchUpdateRecorded",
        "ArchiveResearchUpdateAnnotated",
    }
    pending_update_export = any(
        row["event_type"] in update_event_types and row["published_at"] is None
        for row in _table_rows(actual, "outbox_event").values()
    )
    checkpoints = list(
        _table_rows(actual, "research_update_export_checkpoint").values()
    )
    if len(checkpoints) > 1:
        raise RuntimeSealError("research update export has multiple checkpoints")
    checkpoint = checkpoints[0] if checkpoints else None
    expected_watermark, expected_history_sha256, expected_count = (
        _research_update_export_material(actual)
    )
    if not pending_update_export:
        if (
            checkpoint is None
            or checkpoint["export_name"] != "research_update_history.jsonl"
            or checkpoint["database_watermark"] != expected_watermark
            or checkpoint["history_sha256"] != expected_history_sha256
            or int(checkpoint["row_count"]) != expected_count
        ):
            raise RuntimeSealError(
                "research update export checkpoint differs from database truth"
            )
    elif checkpoint is not None and int(checkpoint["row_count"]) > expected_count:
        raise RuntimeSealError(
            "pending research update export checkpoint exceeds database truth"
        )
    if delivery is not None and checkpoint is not None:
        export_path = delivery / "exports" / "research_update_history.jsonl"
        if (
            not export_path.is_file()
            or file_identity(export_path).get("sha256")
            != checkpoint["history_sha256"]
        ):
            raise RuntimeSealError(
                "research update JSONL differs from its database checkpoint"
            )


def _recompute_blueprint_validation(
    components: list[object], actual: Mapping[str, object]
) -> dict[str, object]:
    """仅从密封 registry/rules 与 canonical request 独立重算验证结果。"""

    errors: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []
    registry = {
        str(row["component_id"]): row
        for row in _table_rows(actual, "concept_component").values()
    }
    normalized: list[dict[str, object]] = []
    selected_rows: dict[str, dict[str, object]] = {}
    for value in components:
        if not isinstance(value, dict):
            raise RuntimeSealError("blueprint request contains a non-object component")
        item = dict(value)
        component_id = str(item.get("component_id") or "")
        row = registry.get(component_id)
        if row is None:
            errors.append({"code": "component_not_found", "component_id": component_id})
        else:
            selected_rows[component_id] = row
        normalized.append(item)
    if errors:
        return {"valid": False, "errors": errors, "warnings": warnings}
    ordered = sorted(
        normalized,
        key=lambda item: (
            int(item.get("layer_order", 0)),
            int(item.get("ordinal", 0)),
        ),
    )
    upstream: set[str] = set()
    selected_legacy: set[str] = set()
    by_layer: dict[str, list[str]] = {}
    for item in ordered:
        row = selected_rows[str(item["component_id"])]
        automatic = _json_object(
            row["automatic_payload_json"], label="component automatic payload"
        )
        selected_legacy.add(str(row["legacy_component_id"]))
        layer = str(item.get("layer") or row["layer"])
        by_layer.setdefault(layer, []).append(str(row["legacy_component_id"]))
        inputs = set(str(value) for value in (automatic.get("input_types") or []))
        if upstream and inputs and not (upstream & inputs):
            target = warnings if bool(item.get("forced")) else errors
            target.append(
                {
                    "code": "type_incompatible",
                    "component_id": item["component_id"],
                    "upstream_outputs": sorted(upstream),
                    "input_types": sorted(inputs),
                }
            )
        outputs = set(str(value) for value in (automatic.get("output_types") or []))
        if outputs:
            upstream = outputs
    rule_rows = sorted(
        (
            row
            for row in _table_rows(actual, "compatibility_rule").values()
            if int(row["active"]) == 1
        ),
        key=lambda row: str(row["legacy_rule_id"]),
    )
    for row in rule_rows:
        rule = _json_object(row["rule_json"], label="compatibility rule")
        if rule.get("trigger_block") not in selected_legacy:
            continue
        target = errors if rule.get("severity", "soft") == "hard" else warnings
        for layer in rule.get("incompatible_layers", []):  # type: ignore[union-attr]
            if by_layer.get(str(layer)):
                target.append({"code": rule.get("id"), "layer": layer})
        required = rule.get("required_upstream_output_type")
        if required and not any(
            required
            in (
                _json_object(
                    selected["automatic_payload_json"],
                    label="component automatic payload",
                ).get("output_types")
                or []
            )
            for selected in selected_rows.values()
        ):
            target.append({"code": rule.get("id"), "required_type": required})
        compatible = set(str(value) for value in (rule.get("compatible_loss_blocks") or []))
        if compatible and not (compatible & selected_legacy):
            target.append(
                {
                    "code": rule.get("id"),
                    "compatible_loss_blocks": sorted(compatible),
                }
            )
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def _validate_paper_lab_closure(
    baseline: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    added_managed_files: Mapping[str, Mapping[str, object]],
) -> None:
    additions = _compare_database_baseline(
        baseline,
        actual,
        append_tables=PAPER_LAB_APPEND_TABLES,
        mutable_tables=PAPER_LAB_MUTABLE_TABLES,
        label="Paper Lab runtime",
    )
    receipts = _new_rows(baseline, actual, "paper_lab_command_receipt")
    blueprint_receipts = [
        row for row in receipts if row["command_kind"] == "save_blueprint"
    ]
    overlay_receipts = [
        row for row in receipts if row["command_kind"] == "save_paper_field"
    ]
    if len(blueprint_receipts) + len(overlay_receipts) != len(receipts):
        raise RuntimeSealError("Paper Lab command is not resume-allowlisted")
    versions = _new_rows(baseline, actual, "blueprint_version")
    all_new_events = _new_rows(baseline, actual, "paper_lab_event")
    events = [
        row
        for row in all_new_events
        if row["event_type"] == "blueprint_version_saved"
    ]
    registration_events = [
        row
        for row in all_new_events
        if row["event_type"] == "paper_drop_registered"
    ]
    overlay_events = [
        row
        for row in all_new_events
        if row["event_type"] == "paper_field_overlay_saved"
    ]
    if len(events) + len(registration_events) + len(overlay_events) != len(all_new_events):
        raise RuntimeSealError("Paper Lab event is not resume-allowlisted")
    allowed_versions: dict[str, str] = {}
    command_by_version: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    allowed_blueprints: set[str] = set()
    for receipt in blueprint_receipts:
        if len(str(receipt["request_sha256"])) != 64:
            raise RuntimeSealError("Paper Lab command request hash is invalid")
        response = _json_object(receipt["response_json"], label="Paper Lab response")
        blueprint_id = str(response.get("blueprint_id", ""))
        version_id = str(response.get("blueprint_version_id", ""))
        if not blueprint_id or not version_id or int(response.get("version", 0)) < 1:
            raise RuntimeSealError("Paper Lab response identity is invalid")
        if version_id in allowed_versions:
            raise RuntimeSealError("Paper Lab version has duplicate command receipts")
        allowed_versions[version_id] = blueprint_id
        command_by_version[version_id] = (receipt, response)
        allowed_blueprints.add(blueprint_id)
    actual_versions = {str(row["blueprint_version_id"]): row for row in versions}
    if set(actual_versions) != set(allowed_versions):
        raise RuntimeSealError("Paper Lab versions do not close over command receipts")
    baseline_version_rows = _table_rows(baseline, "blueprint_version")
    baseline_max_version: dict[str, int] = {}
    for row in baseline_version_rows.values():
        blueprint_id = str(row["blueprint_id"])
        baseline_max_version[blueprint_id] = max(
            baseline_max_version.get(blueprint_id, 0), int(row["version"])
        )
    for blueprint_id in sorted(set(allowed_versions.values())):
        expected_version = baseline_max_version.get(blueprint_id, 0) + 1
        for version in sorted(
            (
                row
                for row in actual_versions.values()
                if row["blueprint_id"] == blueprint_id
            ),
            key=lambda row: int(row["version"]),
        ):
            version_id = str(version["blueprint_version_id"])
            receipt = command_by_version[version_id][0]
            if (
                int(version["version"]) != expected_version
                or version_id
                != stable_public_id(
                    "labblueprintver", blueprint_id, str(expected_version)
                )
                or version["constraints_json"] != "{}"
                or version["created_at"] != receipt["created_at"]
            ):
                raise RuntimeSealError("Paper Lab blueprint version contract is not deterministic")
            expected_version += 1
    for version_id, blueprint_id in allowed_versions.items():
        version = actual_versions[version_id]
        response = command_by_version[version_id][1]
        validation = response.get("validation")
        if version["blueprint_id"] != blueprint_id:
            raise RuntimeSealError("Paper Lab version belongs to another blueprint")
        if int(response["version"]) != int(version["version"]):
            raise RuntimeSealError("Paper Lab response/version sequence differs")
        if not isinstance(validation, dict):
            raise RuntimeSealError("Paper Lab response has no validation result")
        if _json_object(
            version["validation_report_json"], label="blueprint validation report"
        ) != validation:
            raise RuntimeSealError("Paper Lab validation report differs from response")
        expected_status = "valid" if validation.get("valid") is True else "invalid"
        if version["validation_status"] != expected_status:
            raise RuntimeSealError("Paper Lab validation status differs from response")
    actual_events: dict[str, str] = {}
    event_payloads: dict[str, dict[str, object]] = {}
    event_rows_by_version: dict[str, dict[str, object]] = {}
    for event in events:
        if (
            event["aggregate_type"] != "architecture_blueprint"
            or event["event_type"] != "blueprint_version_saved"
        ):
            raise RuntimeSealError("Paper Lab event is not a blueprint save event")
        payload = _json_object(event["payload_json"], label="Paper Lab event")
        version_id = str(payload.get("version_id", ""))
        if version_id in actual_events:
            raise RuntimeSealError("Paper Lab version has duplicate events")
        actual_events[version_id] = str(event["aggregate_id"])
        event_payloads[version_id] = payload
        event_rows_by_version[version_id] = event
    if actual_events != allowed_versions:
        raise RuntimeSealError("Paper Lab events do not close over saved versions")
    components = _new_rows(baseline, actual, "blueprint_component")
    if any(str(row["blueprint_version_id"]) not in allowed_versions for row in components):
        raise RuntimeSealError("Paper Lab component is not part of a saved version")
    blueprints = _table_rows(actual, "architecture_blueprint")
    added_blueprints = {
        str(blueprints[key]["blueprint_id"])
        for key in additions.get("architecture_blueprint", set())
    }
    if not added_blueprints.issubset(allowed_blueprints):
        raise RuntimeSealError("Paper Lab blueprint has no command receipt")
    baseline_blueprints = _rows_by_key(baseline["architecture_blueprint"])  # type: ignore[index]
    actual_blueprint_rows = _rows_by_key(actual["architecture_blueprint"])  # type: ignore[index]
    changed = {
        str(_row_dict(actual["architecture_blueprint"], row)["blueprint_id"])  # type: ignore[index]
        for key, row in actual_blueprint_rows.items()
        if key not in baseline_blueprints
        or row.get("row_sha256") != baseline_blueprints[key].get("row_sha256")
    }
    if not changed.issubset(allowed_blueprints):
        raise RuntimeSealError("Paper Lab blueprint changed without a save receipt")
    blueprint_by_id = {
        str(row["blueprint_id"]): row for row in blueprints.values()
    }
    components_by_version: dict[str, list[dict[str, object]]] = {}
    for component in components:
        components_by_version.setdefault(
            str(component["blueprint_version_id"]), []
        ).append(component)
    for version_id, blueprint_id in allowed_versions.items():
        receipt, response = command_by_version[version_id]
        payload = event_payloads[version_id]
        request = payload.get("request")
        if not isinstance(request, dict) or set(request) != {
            "name",
            "objective",
            "components",
            "blueprint_id",
        }:
            raise RuntimeSealError("Paper Lab event omits the reviewed request")
        request_sha256 = hashlib.sha256(
            canonical_json(request).encode("utf-8")
        ).hexdigest()
        if (
            payload.get("request_sha256") != request_sha256
            or receipt["request_sha256"] != request_sha256
        ):
            raise RuntimeSealError("Paper Lab request/event/receipt hash differs")
        if payload.get("validation") != response.get("validation"):
            raise RuntimeSealError("Paper Lab event/response validation differs")
        version = actual_versions[version_id]
        event = event_rows_by_version[version_id]
        if (
            event["created_at"] != version["created_at"]
            or receipt["created_at"] != version["created_at"]
        ):
            raise RuntimeSealError("Paper Lab blueprint timestamps differ")
        requested_id = request.get("blueprint_id")
        if requested_id is not None and requested_id != blueprint_id:
            raise RuntimeSealError("Paper Lab request targeted another blueprint")
        if requested_id is None and blueprint_id != stable_public_id(
            "labblueprint", str(request.get("name", "")), str(version["created_at"])
        ):
            raise RuntimeSealError("Paper Lab generated blueprint identity is invalid")
        blueprint = blueprint_by_id.get(blueprint_id)
        if blueprint is None:
            raise RuntimeSealError("Paper Lab blueprint row is missing")
        requested_components = request.get("components")
        if not isinstance(requested_components, list):
            raise RuntimeSealError("Paper Lab request components are invalid")
        expected_components = sorted(
            (
                str(item["component_id"]),
                str(item["layer"]),
                int(item.get("ordinal", 0)),
                int(bool(item.get("forced"))),
            )
            for item in requested_components
            if isinstance(item, dict)
        )
        if len(expected_components) != len(requested_components):
            raise RuntimeSealError("Paper Lab request contains a non-object component")
        actual_components = sorted(
            (
                str(item["component_id"]),
                str(item["layer"]),
                int(item["ordinal"]),
                int(item["forced"]),
            )
            for item in components_by_version.get(version_id, [])
        )
        if actual_components != expected_components:
            raise RuntimeSealError("Paper Lab component set differs from its request")
        recomputed_validation = _recompute_blueprint_validation(
            requested_components, actual
        )
        if (
            recomputed_validation != response.get("validation")
            or recomputed_validation
            != _json_object(
                version["validation_report_json"],
                label="blueprint validation report",
            )
        ):
            raise RuntimeSealError("Paper Lab blueprint validation was not independently reproduced")

    for blueprint_id in allowed_blueprints:
        blueprint = blueprint_by_id[blueprint_id]
        ordered_versions = sorted(
            (
                row
                for row in actual_versions.values()
                if row["blueprint_id"] == blueprint_id
            ),
            key=lambda row: int(row["version"]),
        )
        first = ordered_versions[0]
        latest = ordered_versions[-1]
        latest_request = event_payloads[str(latest["blueprint_version_id"])]["request"]
        assert isinstance(latest_request, dict)
        if (
            blueprint["name"] != str(latest_request.get("name", "")).strip()
            or blueprint["objective"] != latest_request.get("objective")
            or (
                blueprint_id in added_blueprints
                and blueprint["lifecycle_status"] != "draft"
            )
            or blueprint["updated_at"] != latest["created_at"]
            or (
                blueprint_id in added_blueprints
                and blueprint["created_at"] != first["created_at"]
            )
        ):
            raise RuntimeSealError("Paper Lab blueprint row is not the latest exact version")

    # 论文字段编辑是公开 PATCH 命令；每个追加 overlay 必须同时闭合到唯一
    # command receipt、唯一事件、确定性版本链与原始 paper version。不能仅因
    # 表是 append-only 就接受任意注入行。
    new_overlays = {
        str(row["overlay_id"]): row
        for row in _new_rows(baseline, actual, "paper_field_overlay")
    }
    all_overlays = {
        str(row["overlay_id"]): row
        for row in _table_rows(actual, "paper_field_overlay").values()
    }
    all_paper_versions = {
        str(row["paper_version_id"]): row
        for row in _table_rows(actual, "lab_paper_version").values()
    }
    overlay_commands: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for receipt in overlay_receipts:
        response = _json_object(receipt["response_json"], label="paper field response")
        overlay_id = str(response.get("overlay_id", ""))
        if not overlay_id or overlay_id in overlay_commands:
            raise RuntimeSealError("paper field response has a duplicate/empty overlay id")
        overlay_commands[overlay_id] = (receipt, response)
    if set(overlay_commands) != set(new_overlays):
        raise RuntimeSealError("paper field overlays do not close over command receipts")

    overlay_events_by_id: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for event in overlay_events:
        payload = _json_object(event["payload_json"], label="paper field event")
        overlay_id = str(payload.get("overlay_id", ""))
        if not overlay_id or overlay_id in overlay_events_by_id:
            raise RuntimeSealError("paper field overlay has duplicate/empty events")
        overlay_events_by_id[overlay_id] = (event, payload)
    if set(overlay_events_by_id) != set(new_overlays):
        raise RuntimeSealError("paper field overlays do not close over events")

    request_fields = {
        "command",
        "paper_id",
        "field_name",
        "value",
        "expected_version",
        "actor_display_name",
        "reason",
    }
    response_fields = {
        "paper_id",
        "paper_version_id",
        "overlay_id",
        "field_name",
        "value",
        "version",
        "replayed",
    }
    event_fields = {
        "overlay_id",
        "paper_id",
        "paper_version_id",
        "field_name",
        "value",
        "version",
        "supersedes_overlay_id",
        "base_content_sha256",
        "request_sha256",
        "request",
    }
    for overlay_id, overlay in new_overlays.items():
        receipt, response = overlay_commands[overlay_id]
        event, event_payload = overlay_events_by_id[overlay_id]
        request = event_payload.get("request")
        if not isinstance(request, dict) or set(request) != request_fields:
            raise RuntimeSealError("paper field event omits its canonical request")
        if set(response) != response_fields or set(event_payload) != event_fields:
            raise RuntimeSealError("paper field response/event contract is not exact")
        request_hash = hashlib.sha256(
            canonical_json(request).encode("utf-8")
        ).hexdigest()
        paper_id = str(request.get("paper_id", ""))
        field_name = str(request.get("field_name", ""))
        version = int(overlay["version"])
        paper_version = all_paper_versions.get(str(overlay["paper_version_id"]))
        paper_versions = [
            row for row in all_paper_versions.values() if row["paper_id"] == paper_id
        ]
        latest_paper_version = (
            max(
                paper_versions,
                key=lambda row: (
                    str(row["created_at"]),
                    str(row["paper_version_id"]),
                ),
            )
            if paper_versions
            else None
        )
        if (
            request.get("command") != "save_paper_field"
            or field_name not in EDITABLE_PAPER_FIELDS
            or receipt["request_sha256"] != request_hash
            or event_payload.get("request_sha256") != request_hash
            or overlay_id
            != stable_public_id("laboverlay", paper_id, field_name, str(version), request_hash)
            or event["aggregate_type"] != "lab_paper"
            or event["aggregate_id"] != paper_id
            or event["created_at"] != overlay["created_at"]
            or receipt["created_at"] != overlay["created_at"]
            or paper_version is None
            or latest_paper_version is None
            or paper_version["paper_version_id"]
            != latest_paper_version["paper_version_id"]
            or paper_version["paper_id"] != paper_id
            or paper_version["content_sha256"] != overlay["base_content_sha256"]
            or int(request.get("expected_version", -1)) + 1 != version
            or overlay["paper_id"] != paper_id
            or overlay["field_name"] != field_name
            or overlay["value_text"] != request.get("value")
            or overlay["actor_kind"] != "local_researcher"
            or overlay["actor_display_name"] != request.get("actor_display_name")
            or overlay["reason"] != request.get("reason")
        ):
            raise RuntimeSealError("paper field overlay differs from its canonical request")
        expected_response = {
            "paper_id": paper_id,
            "paper_version_id": overlay["paper_version_id"],
            "overlay_id": overlay_id,
            "field_name": field_name,
            "value": overlay["value_text"],
            "version": version,
            "replayed": False,
        }
        expected_event = {
            "overlay_id": overlay_id,
            "paper_id": paper_id,
            "paper_version_id": overlay["paper_version_id"],
            "field_name": field_name,
            "value": overlay["value_text"],
            "version": version,
            "supersedes_overlay_id": overlay["supersedes_overlay_id"],
            "base_content_sha256": overlay["base_content_sha256"],
            "request_sha256": request_hash,
            "request": request,
        }
        if response != expected_response or event_payload != expected_event:
            raise RuntimeSealError("paper field row/event/receipt payload differs")
        predecessors = [
            row
            for row in all_overlays.values()
            if row["paper_id"] == paper_id
            and row["field_name"] == field_name
            and int(row["version"]) < version
        ]
        predecessor = (
            max(predecessors, key=lambda row: int(row["version"]))
            if predecessors
            else None
        )
        if (
            (predecessor is None and version != 1)
            or (predecessor is not None and int(predecessor["version"]) != version - 1)
            or overlay["supersedes_overlay_id"]
            != (predecessor["overlay_id"] if predecessor else None)
        ):
            raise RuntimeSealError("paper field overlay version chain is discontinuous")

    lab_versions = {
        str(row["paper_version_id"]): row
        for row in _new_rows(baseline, actual, "lab_paper_version")
    }
    all_lab_versions = {
        str(row["paper_version_id"]): row
        for row in _table_rows(actual, "lab_paper_version").values()
    }
    lab_papers = {
        str(row["paper_id"]): row
        for row in _table_rows(actual, "lab_paper").values()
    }
    baseline_lab_papers = _rows_by_key(baseline["lab_paper"])  # type: ignore[index]
    actual_lab_paper_rows = _rows_by_key(actual["lab_paper"])  # type: ignore[index]
    changed_lab_papers = {
        str(_row_dict(actual["lab_paper"], row)["paper_id"])  # type: ignore[index]
        for key, row in actual_lab_paper_rows.items()
        if key not in baseline_lab_papers
        or row.get("row_sha256") != baseline_lab_papers[key].get("row_sha256")
    }
    registered_versions: set[str] = set()
    registered_papers: set[str] = set()
    baseline_paper_ids = {
        str(_row_dict(baseline["lab_paper"], row)["paper_id"])  # type: ignore[index]
        for row in baseline_lab_papers.values()
    }
    seen_registration_papers = set(baseline_paper_ids)
    registration_times: dict[str, list[str]] = {}
    for event in sorted(
        registration_events,
        key=lambda row: (
            str(row["created_at"]),
            0
            if bool(
                _json_object(row["payload_json"], label="paper-drop event").get(
                    "created"
                )
            )
            else 1,
            str(row["event_id"]),
        ),
    ):
        if event["aggregate_type"] != "lab_paper":
            raise RuntimeSealError("paper-drop event has the wrong aggregate type")
        payload = _json_object(event["payload_json"], label="paper-drop event")
        candidate = payload.get("candidate")
        if not isinstance(candidate, dict):
            raise RuntimeSealError("paper-drop event omits scanner evidence")
        digest = str(candidate.get("content_sha256", ""))
        original = str(candidate.get("original_filename", ""))
        size = int(candidate.get("bytes", -1))
        paper_id = stable_public_id("labpaper", "paper_drop", digest)
        version_id = stable_public_id("labver", paper_id, digest)
        if event["aggregate_id"] != paper_id:
            raise RuntimeSealError("paper-drop aggregate differs from content identity")
        paper = lab_papers.get(paper_id)
        version = all_lab_versions.get(version_id)
        if paper is None or version is None:
            raise RuntimeSealError("paper-drop event has no paper/version closure")
        expected_status = (
            "discovered" if candidate.get("status") == "discovered" else "quarantined"
        )
        expected_discovery = (
            "registered" if candidate.get("status") == "discovered" else "quarantined"
        )
        relative_asset = f"{digest[:2]}/{digest}.pdf"
        if (
            paper["source_kind"] != "paper_drop"
            or paper["canonical_title"] != candidate.get("title_hint")
            or paper["lifecycle_status"] != expected_status
            or version["paper_id"] != paper_id
            or version["content_sha256"] != digest
            or int(version["bytes"]) != size
            or version["media_type"] != "application/pdf"
            or version["original_filename"] != original
            or version["source_location_urn"]
            != f"qrh:paper-drop:{quote(original)}"
            or version["asset_relative_path"] != relative_asset
            or version["discovery_status"] != expected_discovery
        ):
            raise RuntimeSealError("paper-drop database rows differ from scanner evidence")
        expected_created = paper_id not in seen_registration_papers
        if bool(payload.get("created")) != expected_created:
            raise RuntimeSealError("paper-drop created flag differs from activation subset")
        seen_registration_papers.add(paper_id)
        registration_times.setdefault(paper_id, []).append(str(event["created_at"]))
        registered_versions.add(version_id)
        registered_papers.add(paper_id)
    if not set(lab_versions).issubset(registered_versions):
        raise RuntimeSealError("new paper versions do not close over registration events")
    if not changed_lab_papers.issubset(registered_papers):
        raise RuntimeSealError("Paper Lab paper row changed without registration event")
    for paper_id in registered_papers:
        paper = lab_papers[paper_id]
        times = registration_times[paper_id]
        if paper["updated_at"] != max(times):
            raise RuntimeSealError("Paper Lab paper timestamp differs from registration")
        if paper_id not in baseline_paper_ids and paper["created_at"] != min(times):
            raise RuntimeSealError("Paper Lab paper creation timestamp is not first registration")

    expected_added_files: dict[str, dict[str, object]] = {}
    for version_id in lab_versions:
        version = lab_versions[version_id]
        digest = str(version["content_sha256"])
        relative = f"assets/{version['asset_relative_path']}"
        expected_added_files[relative] = {
            "bytes": int(version["bytes"]),
            "sha256": digest,
        }
    if dict(added_managed_files) != expected_added_files:
        raise RuntimeSealError(
            "Paper Lab managed assets do not close over registered paper versions"
        )


def validate_resume_state(
    *,
    receipt: Mapping[str, object],
    project: Path,
    delivery: Path,
    code_root: Path,
    migrations_root: Path,
    launcher_path: Path,
) -> dict[str, object]:
    baseline = receipt.get("runtime_state_after_create_app")
    if not isinstance(baseline, dict):
        raise RuntimeSealError("bootstrap receipt has no post-create_app baseline")
    actual = capture_runtime_state(
        project=project,
        delivery=delivery,
        code_root=code_root,
        migrations_root=migrations_root,
        launcher_path=launcher_path,
    )
    for field in ("launcher", "code", "migrations", "toolchain", "sources"):
        assert_material(actual.get(field), baseline.get(field), label=f"resume {field}")
    baseline_trees = baseline.get("managed_trees")
    actual_trees = actual.get("managed_trees")
    if not isinstance(baseline_trees, dict) or not isinstance(actual_trees, dict):
        raise RuntimeSealError("bootstrap receipt has no managed file baseline")
    paper_lab_added_files: dict[str, Mapping[str, object]] = {}
    for name in MANAGED_TREE_NAMES:
        expected_tree = baseline_trees.get(name)
        current_tree = actual_trees.get(name)
        if not isinstance(expected_tree, dict) or not isinstance(current_tree, dict):
            raise RuntimeSealError(f"managed tree contract is missing: {name}")
        expected_files = expected_tree.get("files")
        current_files = current_tree.get("files")
        if not isinstance(expected_files, dict) or not isinstance(current_files, dict):
            raise RuntimeSealError(f"managed file manifest is invalid: {name}")
        missing = set(expected_files) - set(current_files)
        changed = {
            relative
            for relative in expected_files.keys() & current_files.keys()
            if expected_files[relative] != current_files[relative]
        }
        added = {
            relative: current_files[relative]
            for relative in sorted(set(current_files) - set(expected_files))
        }
        if name == "exports":
            allowed = {"research_update_history.jsonl"}
            if missing or added or changed - allowed:
                raise RuntimeSealError(
                    "managed research-update export changed outside its closed file"
                )
            if not changed:
                assert_material(
                    current_tree.get("state"),
                    expected_tree.get("state"),
                    label="managed tree exports",
                )
            continue
        if missing or changed:
            raise RuntimeSealError(f"managed activation files changed or disappeared: {name}")
        if name == "paper_lab":
            paper_lab_added_files = added
        elif added:
            raise RuntimeSealError(f"sealed material changed: managed files {name}")
        else:
            assert_material(
                current_tree.get("state"),
                expected_tree.get("state"),
                label=f"managed tree {name}",
            )
    baseline_databases = baseline.get("databases")
    actual_databases = actual.get("databases")
    if not isinstance(baseline_databases, dict) or not isinstance(actual_databases, dict):
        raise RuntimeSealError("bootstrap receipt has no database baseline")
    platform_database = actual_databases.get("platform.sqlite3")
    if not isinstance(platform_database, dict) or not isinstance(
        platform_database.get("row_manifest"), dict
    ):
        raise RuntimeSealError("platform review-certificate manifest is missing")
    platform_row_manifest = platform_database["row_manifest"]
    for name in DATABASE_NAMES:
        before = baseline_databases.get(name)
        now = actual_databases.get(name)
        if not isinstance(before, dict) or not isinstance(now, dict):
            raise RuntimeSealError(f"database baseline is missing: {name}")
        expected_state = before.get("state")
        current_state = now.get("state")
        if not isinstance(expected_state, dict) or not isinstance(current_state, dict):
            raise RuntimeSealError(f"database state is invalid: {name}")
        immutable = ("integrity", "foreign_key_violations", "migration_versions", "schema_sha256")
        assert_material(
            {field: current_state.get(field) for field in immutable},
            {field: expected_state.get(field) for field in immutable},
            label=f"resume database schema {name}",
        )
        before_rows = before.get("row_manifest")
        current_rows = now.get("row_manifest")
        if not isinstance(before_rows, dict) or not isinstance(current_rows, dict):
            raise RuntimeSealError(f"database row manifest is invalid: {name}")
        if name == "archive.sqlite3":
            _validate_archive_closure(
                before_rows,
                current_rows,
                platform_actual=platform_row_manifest,
                delivery=delivery,
            )
        elif name == "paper_lab.sqlite3":
            _validate_paper_lab_closure(
                before_rows,
                current_rows,
                added_managed_files=paper_lab_added_files,
            )
        else:
            _compare_database_baseline(
                before_rows,
                current_rows,
                append_tables=set(),
                mutable_tables={},
                label=f"{name} runtime",
            )
    return actual


def publish_or_validate_strict_receipt(
    *,
    receipt_path: Path,
    project: Path,
    delivery: Path,
    activation_path: Path,
    startup_gate_path: Path,
    before: Mapping[str, object],
    after: Mapping[str, object],
    existed_before_launch: bool,
) -> dict[str, object]:
    if existed_before_launch:
        receipt = load_bootstrap_receipt(
            receipt_path=receipt_path,
            project=project,
            delivery=delivery,
            activation_path=activation_path,
            startup_gate_path=startup_gate_path,
        )
        assert_material(
            receipt.get("runtime_state_after_create_app"),
            after,
            label="repeated strict bootstrap state",
        )
        return receipt
    receipt = make_bootstrap_receipt(
        project=project,
        delivery=delivery,
        activation_path=activation_path,
        startup_gate_path=startup_gate_path,
        before=before,
        after=after,
    )
    try:
        write_atomic_new_json(receipt_path, receipt)
    except FileExistsError as error:
        raise RuntimeSealError("concurrent strict bootstrap receipt publication") from error
    return load_bootstrap_receipt(
        receipt_path=receipt_path,
        project=project,
        delivery=delivery,
        activation_path=activation_path,
        startup_gate_path=startup_gate_path,
    )


__all__ = [
    "BOOTSTRAP_POLICY_VERSION",
    "BOOTSTRAP_RECEIPT_SCHEMA",
    "INITIAL_LAUNCH_MODE",
    "MUTATION_POLICY_VERSION",
    "bootstrap_receipt_path",
    "capture_runtime_state",
    "load_bootstrap_receipt",
    "publish_or_validate_strict_receipt",
    "validate_resume_state",
    "validate_startup_bootstrap_contract",
    "validate_untrusted_paper_ingress",
]
