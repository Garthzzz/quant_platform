"""Exact release 侧的 SQLite compatibility 计划与持久证据。

本模块只证明 release manifest 所声明的 read/write compatibility、固定逻辑 schema
合同以及 exact migration closure 相互一致。它不读取 live state，不观察 SCM/进程，
不形成 writer lease，也绝不产生 deployment qualification。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping, Sequence
import unicodedata

from . import local_release_identity as _identity
from .local_deployment_persistence import LockedExactReleaseClosures


EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCHEMA = (
    "qrh-exact-release-compatibility-evidence/v1"
)
EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE = (
    "exact_release_compatibility_evidence_only"
)
ROLLBACK_POLICY = "expand_only_no_down_migration"
DATABASE_ORDER = ("comments", "research_workspace")
OPERATION_ORDER = ("activation", "rollback", "bootstrap_first_pair")

WORKSPACE_MIGRATIONS = (
    "migrations/research_workspace/0001_research_workspace.down.sql",
    "migrations/research_workspace/0001_research_workspace.up.sql",
    "migrations/research_workspace/0002_project_semantics.down.sql",
    "migrations/research_workspace/0002_project_semantics.up.sql",
    "migrations/research_workspace/0003_project_creation_command.down.sql",
    "migrations/research_workspace/0003_project_creation_command.up.sql",
)

COMMENTS_LOGICAL_SCHEMA = {
    "logical_version": 2,
    "comment_store_schema": [1, 2],
    "comment_target_schema": [3],
}
WORKSPACE_LOGICAL_SCHEMA = {
    "logical_version": 3,
    "schema_migrations": [
        {
            "version": 1,
            "name": "research_workspace",
            "down_path": WORKSPACE_MIGRATIONS[0],
            "up_path": WORKSPACE_MIGRATIONS[1],
        },
        {
            "version": 2,
            "name": "project_semantics",
            "down_path": WORKSPACE_MIGRATIONS[2],
            "up_path": WORKSPACE_MIGRATIONS[3],
        },
        {
            "version": 3,
            "name": "project_creation_command",
            "down_path": WORKSPACE_MIGRATIONS[4],
            "up_path": WORKSPACE_MIGRATIONS[5],
        },
    ],
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_EVIDENCE_SET_TOKEN = object()


class ExactReleaseCompatibilityError(RuntimeError):
    """Release-side compatibility plan/evidence 不满足 closed contract。"""


def _closed(value: object, fields: set[str], *, label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ExactReleaseCompatibilityError(f"{label} schema is not closed")
    return value


def _identifier(value: object, *, label: str) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise ExactReleaseCompatibilityError(f"{label} is not a safe identifier")
    normalized = unicodedata.normalize("NFKC", value)
    if normalized != value or value.endswith((".", " ")):
        raise ExactReleaseCompatibilityError(f"{label} has a Windows alias")
    if normalized.split(".", 1)[0].casefold() in _WINDOWS_DEVICE_NAMES:
        raise ExactReleaseCompatibilityError(f"{label} is a Windows device alias")
    return value


def _sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or not _SHA256_RE.fullmatch(value)
        or value == "0" * 64
    ):
        raise ExactReleaseCompatibilityError(f"{label} is not a sealed SHA-256")
    return value


def _canonical_clone(value: object) -> object:
    return json.loads(_identity.canonical_bytes(value).decode("utf-8"))


def _self_hash(value: Mapping[str, object], field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    return _identity.identity_sha256(material)


def _release_ref_from_manifest(manifest: Mapping[str, object]) -> Mapping[str, object]:
    release_id = str(manifest["release_id"])
    reference = {
        "release_id": release_id,
        "release_path": (
            f"D:\\quant\\quant_platform\\releases\\{release_id}"
        ),
        "manifest_sha256": _identity.identity_sha256(manifest),
    }
    active = _identity.validate_active_release(
        {
            "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
            "release": reference,
        }
    )
    return active["release"]


def _validate_release_ref(value: object, *, label: str) -> Mapping[str, object]:
    try:
        active = _identity.validate_active_release(
            {
                "schema_version": _identity.ACTIVE_RELEASE_SCHEMA,
                "release": value,
            }
        )
    except Exception as error:
        raise ExactReleaseCompatibilityError(
            f"{label} is not an exact B1 D-root release ref"
        ) from error
    return active["release"]


def _versions(value: object, *, label: str, current: int) -> list[int]:
    if (
        type(value) is not list
        or not value
        or any(type(item) is not int or item < 1 for item in value)
        or value != sorted(set(value))
        or current not in value
    ):
        raise ExactReleaseCompatibilityError(
            f"{label} must be sorted unique and include current logical version"
        )
    return value


def _logical_schema(database_name: str) -> Mapping[str, object]:
    return _canonical_clone(
        COMMENTS_LOGICAL_SCHEMA
        if database_name == "comments"
        else WORKSPACE_LOGICAL_SCHEMA
    )  # type: ignore[return-value]


def _schema_contract_sha256(
    database_name: str,
    logical_schema: Mapping[str, object],
) -> str:
    return _identity.identity_sha256(
        {
            "database_name": database_name,
            "logical_schema": logical_schema,
            "rollback_policy": ROLLBACK_POLICY,
        }
    )


def _migration_files_from_manifest(
    manifest: Mapping[str, object], database_name: str
) -> list[Mapping[str, object]]:
    if database_name == "comments":
        return []
    inventory = {
        str(item["path"]): item for item in manifest["inventory"]["files"]
    }
    observed = {
        path
        for path in inventory
        if path.startswith("migrations/research_workspace/")
    }
    if observed != set(WORKSPACE_MIGRATIONS):
        raise ExactReleaseCompatibilityError(
            "research_workspace manifest migration set is not exact"
        )
    return [
        {
            "path": path,
            "bytes": int(inventory[path]["bytes"]),
            "sha256": str(inventory[path]["sha256"]),
        }
        for path in WORKSPACE_MIGRATIONS
    ]


def _release_material(
    *,
    manifest: Mapping[str, object],
    role: str,
    database_name: str,
) -> Mapping[str, object]:
    compatibility = manifest["state"]["compatibility"][database_name]
    material: dict[str, object] = {
        "role": role,
        "release": _release_ref_from_manifest(manifest),
        "inventory_sha256": manifest["resources"]["inventory_sha256"],
        "sealed_core_sha256": _identity.sealed_release_core_sha256(manifest),
        "read_versions": list(compatibility["read"]),
        "write_versions": list(compatibility["write"]),
        "migration_files": _migration_files_from_manifest(
            manifest, database_name
        ),
    }
    material["material_sha256"] = _identity.identity_sha256(material)
    return material


def _validate_migration_files(
    value: object, *, database_name: str
) -> list[Mapping[str, object]]:
    if type(value) is not list:
        raise ExactReleaseCompatibilityError("migration_files must be a list")
    if database_name == "comments":
        if value:
            raise ExactReleaseCompatibilityError(
                "comments compatibility must not contain migration files"
            )
        return value
    records: list[Mapping[str, object]] = []
    paths: list[str] = []
    for raw in value:
        record = _closed(
            raw,
            {"path", "bytes", "sha256"},
            label="workspace migration record",
        )
        path = record["path"]
        if type(path) is not str or path not in WORKSPACE_MIGRATIONS:
            raise ExactReleaseCompatibilityError(
                "workspace migration path is outside the fixed enum"
            )
        if type(record["bytes"]) is not int or int(record["bytes"]) < 0:
            raise ExactReleaseCompatibilityError("migration bytes is invalid")
        _sha256(record["sha256"], label="migration sha256")
        paths.append(path)
        records.append(record)
    if paths != list(WORKSPACE_MIGRATIONS):
        raise ExactReleaseCompatibilityError(
            "workspace migration files must be the exact lexical six"
        )
    return records


def _validate_release_material(
    value: object,
    *,
    role: str,
    database_name: str,
    current: int,
) -> Mapping[str, object]:
    material = _closed(
        value,
        {
            "role",
            "release",
            "inventory_sha256",
            "sealed_core_sha256",
            "read_versions",
            "write_versions",
            "migration_files",
            "material_sha256",
        },
        label=f"{role} release material",
    )
    if material["role"] != role:
        raise ExactReleaseCompatibilityError("release material role differs")
    _validate_release_ref(material["release"], label=f"{role} release")
    _sha256(material["inventory_sha256"], label=f"{role} inventory")
    _sha256(material["sealed_core_sha256"], label=f"{role} sealed core")
    _versions(material["read_versions"], label=f"{role} read", current=current)
    _versions(material["write_versions"], label=f"{role} write", current=current)
    _validate_migration_files(
        material["migration_files"], database_name=database_name
    )
    expected = _self_hash(material, "material_sha256")
    if _sha256(material["material_sha256"], label=f"{role} material") != expected:
        raise ExactReleaseCompatibilityError("release material self hash differs")
    return material


def _validate_logical_schema(
    value: object, *, database_name: str
) -> Mapping[str, object]:
    expected = _logical_schema(database_name)
    if type(value) is not dict or value != expected:
        raise ExactReleaseCompatibilityError(
            f"{database_name} logical schema contract differs"
        )
    return value


def validate_exact_release_compatibility_evidence(
    value: object,
) -> Mapping[str, object]:
    """纯验证一份持久 compatibility evidence；不产生任何运行资格。"""

    document = _closed(
        value,
        {
            "schema_version",
            "attempt_id",
            "nonce",
            "operation",
            "database_name",
            "evidence_scope",
            "state_identity_sha256",
            "logical_schema",
            "release_qualification",
            "rollback_policy",
            "schema_contract_sha256",
            "evidence_sha256",
        },
        label="exact release compatibility evidence",
    )
    if document["schema_version"] != EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCHEMA:
        raise ExactReleaseCompatibilityError("compatibility evidence schema differs")
    _identifier(document["attempt_id"], label="attempt_id")
    _identifier(document["nonce"], label="nonce")
    operation = document["operation"]
    if type(operation) is not str or operation not in OPERATION_ORDER:
        raise ExactReleaseCompatibilityError("compatibility operation differs")
    database_name = document["database_name"]
    if type(database_name) is not str or database_name not in DATABASE_ORDER:
        raise ExactReleaseCompatibilityError("compatibility database differs")
    if document["evidence_scope"] != EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE:
        raise ExactReleaseCompatibilityError("compatibility evidence scope differs")
    _sha256(document["state_identity_sha256"], label="state identity")
    logical = _validate_logical_schema(
        document["logical_schema"], database_name=database_name
    )
    if document["rollback_policy"] != ROLLBACK_POLICY:
        raise ExactReleaseCompatibilityError("rollback policy differs")
    expected_contract = _schema_contract_sha256(database_name, logical)
    if (
        _sha256(document["schema_contract_sha256"], label="schema contract")
        != expected_contract
    ):
        raise ExactReleaseCompatibilityError("schema contract hash differs")

    qualification = document["release_qualification"]
    current = int(logical["logical_version"])
    if operation == "bootstrap_first_pair":
        bound = _closed(
            qualification,
            {"kind", "candidate", "prior"},
            label="bootstrap release qualification",
        )
        if bound["kind"] != "bootstrap_baseline":
            raise ExactReleaseCompatibilityError("bootstrap kind differs")
        _validate_release_material(
            bound["candidate"],
            role="candidate",
            database_name=database_name,
            current=current,
        )
        absent = _closed(
            bound["prior"], {"status"}, label="bootstrap absent prior"
        )
        if absent["status"] != "absent":
            raise ExactReleaseCompatibilityError("bootstrap prior is not absent")
    else:
        bound = _closed(
            qualification,
            {"kind", "candidate", "prior"},
            label="ordinary release qualification",
        )
        if bound["kind"] != "release_pair":
            raise ExactReleaseCompatibilityError("ordinary pair kind differs")
        candidate = _validate_release_material(
            bound["candidate"],
            role="candidate",
            database_name=database_name,
            current=current,
        )
        prior = _validate_release_material(
            bound["prior"],
            role="prior",
            database_name=database_name,
            current=current,
        )
        if (
            candidate["release"]["release_id"]
            == prior["release"]["release_id"]
            or candidate["release"]["manifest_sha256"]
            == prior["release"]["manifest_sha256"]
            or candidate["sealed_core_sha256"] == prior["sealed_core_sha256"]
        ):
            raise ExactReleaseCompatibilityError(
                "candidate/prior IDs, manifests and sealed cores must differ"
            )
    expected_evidence = _self_hash(document, "evidence_sha256")
    if (
        _sha256(document["evidence_sha256"], label="compatibility evidence")
        != expected_evidence
    ):
        raise ExactReleaseCompatibilityError("compatibility evidence self hash differs")
    return document


def validate_exact_release_compatibility_evidence_set(
    documents: object,
) -> tuple[tuple[Mapping[str, object], ...], str]:
    """验证 comments/workspace 两份证据并返回 fixed-order aggregate。"""

    if type(documents) not in {list, tuple} or len(documents) != 2:
        raise ExactReleaseCompatibilityError(
            "compatibility evidence set must contain exactly two documents"
        )
    validated = tuple(
        validate_exact_release_compatibility_evidence(item) for item in documents
    )
    if tuple(item["database_name"] for item in validated) != DATABASE_ORDER:
        raise ExactReleaseCompatibilityError(
            "compatibility evidence database order differs"
        )
    identity_fields = ("attempt_id", "nonce", "operation", "state_identity_sha256")
    if any(
        validated[0][field] != validated[1][field] for field in identity_fields
    ):
        raise ExactReleaseCompatibilityError(
            "compatibility evidence set identity differs"
        )
    first_qualification = validated[0]["release_qualification"]
    second_qualification = validated[1]["release_qualification"]
    if first_qualification["kind"] != second_qualification["kind"]:
        raise ExactReleaseCompatibilityError(
            "compatibility evidence release qualification kind differs"
        )
    roles = ("candidate",)
    if first_qualification["kind"] == "release_pair":
        roles = ("candidate", "prior")
    for role in roles:
        first_material = first_qualification[role]
        second_material = second_qualification[role]
        for field in ("release", "inventory_sha256", "sealed_core_sha256"):
            if first_material[field] != second_material[field]:
                raise ExactReleaseCompatibilityError(
                    "compatibility evidence release manifest set differs"
                )
    if roles == ("candidate",) and (
        first_qualification["prior"] != {"status": "absent"}
        or second_qualification["prior"] != {"status": "absent"}
    ):
        raise ExactReleaseCompatibilityError(
            "bootstrap compatibility evidence prior differs"
        )
    aggregate = _identity.identity_sha256(
        [
            {
                "name": document["database_name"],
                "compatibility_manifest_sha256": document["evidence_sha256"],
            }
            for document in validated
        ]
    )
    return validated, aggregate


def _build_document(
    *,
    operation: str,
    attempt_id: str,
    nonce: str,
    state_identity_sha256: str,
    database_name: str,
    candidate: Mapping[str, object],
    prior: Mapping[str, object] | None,
) -> Mapping[str, object]:
    logical = _logical_schema(database_name)
    candidate_material = _release_material(
        manifest=candidate,
        role="candidate",
        database_name=database_name,
    )
    if operation == "bootstrap_first_pair":
        qualification: Mapping[str, object] = {
            "kind": "bootstrap_baseline",
            "candidate": candidate_material,
            "prior": {"status": "absent"},
        }
    else:
        if prior is None:
            raise ExactReleaseCompatibilityError("ordinary plan requires prior manifest")
        qualification = {
            "kind": "release_pair",
            "candidate": candidate_material,
            "prior": _release_material(
                manifest=prior,
                role="prior",
                database_name=database_name,
            ),
        }
    document: dict[str, object] = {
        "schema_version": EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCHEMA,
        "attempt_id": attempt_id,
        "nonce": nonce,
        "operation": operation,
        "database_name": database_name,
        "evidence_scope": EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE,
        "state_identity_sha256": state_identity_sha256,
        "logical_schema": logical,
        "release_qualification": qualification,
        "rollback_policy": ROLLBACK_POLICY,
        "schema_contract_sha256": _schema_contract_sha256(
            database_name, logical
        ),
    }
    document["evidence_sha256"] = _identity.identity_sha256(document)
    return document


@dataclass(frozen=True, slots=True)
class ExactReleaseCompatibilityPlan:
    """Revision 0 前的纯计划；只公开 aggregate，不携带证据文档。"""

    aggregate_sha256: str

    @property
    def scope(self) -> str:
        return "plan_only"

class LockedExactReleaseCompatibilityEvidenceSet:
    """由 live exact closure 重建的进程内 evidence-only 结果。"""

    __slots__ = ("_documents", "_aggregate_sha256")

    def __init__(
        self,
        *,
        documents: Sequence[Mapping[str, object]],
        aggregate_sha256: str,
        _construction_token: object,
    ):
        if _construction_token is not _EVIDENCE_SET_TOKEN:
            raise ExactReleaseCompatibilityError(
                "compatibility evidence set must be built from exact closures"
            )
        self._documents = tuple(
            _canonical_clone(document) for document in documents
        )
        self._aggregate_sha256 = aggregate_sha256

    def __reduce__(self) -> object:
        raise TypeError(
            "exact release compatibility evidence set is process-local"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        return EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE

    @property
    def aggregate_sha256(self) -> str:
        return self._aggregate_sha256

    @property
    def documents(self) -> tuple[Mapping[str, object], ...]:
        return tuple(
            _canonical_clone(document)  # type: ignore[arg-type]
            for document in self._documents
        )

    def document(self, database_name: str) -> Mapping[str, object]:
        if type(database_name) is not str or database_name not in DATABASE_ORDER:
            raise ExactReleaseCompatibilityError("database name is not fixed")
        for document in self._documents:
            if document["database_name"] == database_name:
                return _canonical_clone(document)  # type: ignore[return-value]
        raise ExactReleaseCompatibilityError("database evidence is absent")


def plan_exact_release_compatibility(
    *,
    operation: str,
    attempt_id: str,
    nonce: str,
    state_identity_sha256: str,
    candidate_manifest: object,
    prior_manifest: object | None,
) -> ExactReleaseCompatibilityPlan:
    """从完整 B1 manifests 计算 revision-0 compatibility intent。"""

    if type(operation) is not str or operation not in OPERATION_ORDER:
        raise ExactReleaseCompatibilityError("plan operation differs")
    _identifier(attempt_id, label="attempt_id")
    _identifier(nonce, label="nonce")
    _sha256(state_identity_sha256, label="state identity")
    try:
        candidate = _identity.validate_release_manifest(candidate_manifest)
    except Exception as error:
        raise ExactReleaseCompatibilityError(
            "candidate is not a complete B1 v2 manifest"
        ) from error
    if operation == "bootstrap_first_pair":
        if prior_manifest is not None:
            raise ExactReleaseCompatibilityError(
                "bootstrap plan must have an absent prior"
            )
        prior = None
    else:
        if prior_manifest is None:
            raise ExactReleaseCompatibilityError(
                "ordinary plan requires a complete prior manifest"
            )
        try:
            prior = _identity.validate_release_manifest(prior_manifest)
        except Exception as error:
            raise ExactReleaseCompatibilityError(
                "prior is not a complete B1 v2 manifest"
            ) from error
    documents = tuple(
        _build_document(
            operation=operation,
            attempt_id=attempt_id,
            nonce=nonce,
            state_identity_sha256=state_identity_sha256,
            database_name=database_name,
            candidate=candidate,
            prior=prior,
        )
        for database_name in DATABASE_ORDER
    )
    validated, aggregate = validate_exact_release_compatibility_evidence_set(
        documents
    )
    # ``validated`` 只用于计算 revision-0 intent；计划对象故意不暴露这些
    # evidence-shaped 中间材料，避免调用方把未经过 live closure 的计划误存为证据。
    del validated
    return ExactReleaseCompatibilityPlan(aggregate_sha256=aggregate)


def build_exact_release_compatibility_evidence(
    closures: LockedExactReleaseClosures,
) -> LockedExactReleaseCompatibilityEvidenceSet:
    """从 exact live closure 重建持久证据；结果仍不是部署资格。"""

    if type(closures) is not LockedExactReleaseClosures:
        raise ExactReleaseCompatibilityError(
            "builder requires the exact LockedExactReleaseClosures type"
        )
    # 每个 public property 都会重验 live workspace/thread/epoch。
    operation = closures.operation
    roles = closures.roles
    if roles not in {("candidate",), ("candidate", "prior")}:
        raise ExactReleaseCompatibilityError("exact closure roles differ")
    candidate = closures.read_manifest("candidate")
    prior = (
        None if roles == ("candidate",) else closures.read_manifest("prior")
    )
    plan = plan_exact_release_compatibility(
        operation=operation,
        attempt_id=closures.attempt_id,
        nonce=closures.nonce,
        state_identity_sha256=closures.state_identity_sha256,
        candidate_manifest=candidate,
        prior_manifest=prior,
    )
    if plan.aggregate_sha256 != closures.planned_compatibility_sha256:
        raise ExactReleaseCompatibilityError(
            "live exact closure evidence differs from planned aggregate"
        )
    metadata = closures.metadata()
    role_metadata = metadata["roles"]
    for role in roles:
        observed_role = role_metadata[role]
        manifest = candidate if role == "candidate" else prior
        if manifest is None:
            raise ExactReleaseCompatibilityError("ordinary prior manifest is absent")
        reference = _release_ref_from_manifest(manifest)
        expected_role = {
            "release_id": reference["release_id"],
            "manifest_sha256": reference["manifest_sha256"],
            "inventory_sha256": manifest["resources"]["inventory_sha256"],
            "sealed_core_sha256": _identity.sealed_release_core_sha256(manifest),
        }
        if any(observed_role[field] != value for field, value in expected_role.items()):
            raise ExactReleaseCompatibilityError(
                "closure metadata differs from pinned manifest"
            )
        migrations = observed_role["migrations"]
        if [item["relative_path"] for item in migrations] != list(
            WORKSPACE_MIGRATIONS
        ):
            raise ExactReleaseCompatibilityError(
                "closure migration metadata differs from fixed enum"
            )
        for item in migrations:
            raw = closures.read_migration(role, str(item["relative_path"]))
            if (
                len(raw) != item["bytes"]
                or hashlib.sha256(raw).hexdigest() != item["sha256"]
            ):
                raise ExactReleaseCompatibilityError(
                    "closure migration bytes differ from pinned metadata"
                )
    documents = tuple(
        _build_document(
            operation=operation,
            attempt_id=closures.attempt_id,
            nonce=closures.nonce,
            state_identity_sha256=closures.state_identity_sha256,
            database_name=database_name,
            candidate=candidate,
            prior=prior,
        )
        for database_name in DATABASE_ORDER
    )
    validated, aggregate = validate_exact_release_compatibility_evidence_set(
        documents
    )
    if aggregate != plan.aggregate_sha256:
        raise ExactReleaseCompatibilityError(
            "live evidence aggregate differs after closure verification"
        )
    return LockedExactReleaseCompatibilityEvidenceSet(
        documents=validated,
        aggregate_sha256=aggregate,
        _construction_token=_EVIDENCE_SET_TOKEN,
    )


__all__ = [
    "COMMENTS_LOGICAL_SCHEMA",
    "DATABASE_ORDER",
    "EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCHEMA",
    "EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE",
    "ExactReleaseCompatibilityError",
    "ExactReleaseCompatibilityPlan",
    "LockedExactReleaseCompatibilityEvidenceSet",
    "ROLLBACK_POLICY",
    "WORKSPACE_LOGICAL_SCHEMA",
    "WORKSPACE_MIGRATIONS",
    "build_exact_release_compatibility_evidence",
    "plan_exact_release_compatibility",
    "validate_exact_release_compatibility_evidence",
    "validate_exact_release_compatibility_evidence_set",
]
