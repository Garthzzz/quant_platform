from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import stat

from quant_hub.config import (
    ConfigurationError,
    Settings,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)
from quant_hub.platform.migrations import schema_hash
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.ids import stable_sha256

from .database import evidence_connection
from .bulk import import_bulk_evidence
from .export import export_candidate_inventory, export_inventory
from .fixture import import_vertical_fixture
from .releases import EvidenceReleaseService
from .resources import EvidenceResourceStore


_REPLAY_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class EvidenceReplayError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceReplayResult:
    replay_slug: str
    replay_root: Path
    schema_hash: str
    inventory_sha256: str
    inventory_bytes: int
    candidate_inventory_sha256: str | None
    candidate_inventory_bytes: int
    evidence_release_id: str | None
    release_snapshot_urn: str | None
    active_revision: int
    release_created: bool
    resource_count: int
    counts: dict[str, int]


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _overlaps(left: Path, right: Path) -> bool:
    return _is_relative_to(left, right) or _is_relative_to(right, left)


def _managed_target(settings: Settings, replay_slug: str) -> Path:
    if not _REPLAY_SLUG_RE.fullmatch(replay_slug):
        raise EvidenceReplayError("replay target must be a safe direct-child slug")
    settings.ensure_runtime_directories()
    managed_root = settings.evidence_replay_root.absolute()
    try:
        ensure_no_reparse_components(managed_root)
        root_info = managed_root.lstat()
    except (ConfigurationError, OSError) as error:
        raise EvidenceReplayError("managed replay root is unsafe") from error
    if not stat.S_ISDIR(root_info.st_mode) or stat_is_reparse_point(root_info):
        raise EvidenceReplayError("managed replay root must be a real directory")
    target = managed_root / replay_slug
    if target.parent != managed_root:
        raise EvidenceReplayError("replay target must be a direct child")

    unresolved_target = target.absolute()
    sensitive = (
        settings.archive_root.resolve(strict=True),
        (settings.project_root / "reference").resolve(strict=True),
        settings.database_path.resolve(strict=False),
        settings.archive_database_path.resolve(strict=False),
        settings.research_papers_database_path.resolve(strict=False),
        settings.paper_lab_database_path.resolve(strict=False),
        settings.object_root.resolve(strict=False),
        settings.research_papers_root.resolve(strict=False),
        settings.paper_lab_asset_root.resolve(strict=False),
        settings.migration_root.resolve(strict=True),
        settings.research_papers_migration_root.resolve(strict=True),
    )
    for protected in sensitive:
        if _overlaps(unresolved_target, protected):
            raise EvidenceReplayError(f"replay target overlaps a protected path: {protected}")

    try:
        ensure_no_reparse_components(target)
        target.mkdir(exist_ok=True)
        ensure_no_reparse_components(target)
        info = target.lstat()
    except (ConfigurationError, OSError) as error:
        raise EvidenceReplayError("replay target cannot be created safely") from error
    if not stat.S_ISDIR(info.st_mode) or stat_is_reparse_point(info):
        raise EvidenceReplayError("replay target must be a real directory")
    if any(target.iterdir()):
        raise EvidenceReplayError("replay target must be new or empty")
    return target


def run_managed_replay(
    settings: Settings,
    *,
    replay_slug: str,
    fixture_manifest: Path,
) -> EvidenceReplayResult:
    """在受管空子树内执行 migration、五类导入、资源与导出复核。"""

    target = _managed_target(settings, replay_slug)
    isolated = Settings(
        project_root=settings.project_root,
        archive_root=settings.archive_root,
        var_root=target,
        database_path=target / "db" / "platform.sqlite3",
        object_root=target / "objects",
        migration_root=settings.migration_root,
    )
    isolated.validate()
    imported = import_vertical_fixture(isolated, fixture_manifest)
    repeated_export = export_inventory(isolated)
    if (
        repeated_export.content_sha256 != imported.inventory.content_sha256
        or repeated_export.bytes != imported.inventory.bytes
        or repeated_export.relative_path != imported.inventory.relative_path
    ):
        raise EvidenceReplayError("repeated deterministic inventory bytes differ")

    resource_store = EvidenceResourceStore(isolated)
    with evidence_connection(isolated) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        current_schema_hash = schema_hash(connection)
        resource_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id"
            )
        ]
    if integrity != "ok" or foreign_keys:
        raise EvidenceReplayError("isolated replay database failed integrity checks")
    for resource_id in resource_ids:
        resource_store.resource_response(resource_id)
    if len(resource_ids) != imported.counts["paper_resource"]:
        raise EvidenceReplayError("resource verification count differs from replay database")
    return EvidenceReplayResult(
        replay_slug=replay_slug,
        replay_root=target,
        schema_hash=current_schema_hash,
        inventory_sha256=imported.inventory.content_sha256,
        inventory_bytes=imported.inventory.bytes,
        candidate_inventory_sha256=None,
        candidate_inventory_bytes=0,
        evidence_release_id=None,
        release_snapshot_urn=None,
        active_revision=0,
        release_created=False,
        resource_count=len(resource_ids),
        counts=imported.counts,
    )


def run_managed_bulk_replay(
    settings: Settings,
    *,
    replay_slug: str,
    package_root: Path,
    normalized_manifest_path: Path | None = None,
) -> EvidenceReplayResult:
    """在新的受管子树内完整回放 E 245/5,181/18 数据包。"""

    target = _managed_target(settings, replay_slug)
    isolated = Settings(
        project_root=settings.project_root,
        archive_root=settings.archive_root,
        var_root=target,
        database_path=target / "db" / "platform.sqlite3",
        object_root=target / "objects",
        migration_root=settings.migration_root,
    )
    isolated.validate()
    imported = import_bulk_evidence(
        isolated,
        package_root,
        normalized_manifest_path=normalized_manifest_path,
    )
    replayed = import_bulk_evidence(
        isolated,
        package_root,
        normalized_manifest_path=normalized_manifest_path,
    )
    repeated_export = export_inventory(isolated)
    repeated_candidate_export = export_candidate_inventory(isolated)
    if replayed.created:
        raise EvidenceReplayError("second bulk import was not idempotent")
    if (
        repeated_export.content_sha256 != imported.inventory.content_sha256
        or repeated_export.bytes != imported.inventory.bytes
        or repeated_export.relative_path != imported.inventory.relative_path
        or repeated_candidate_export.content_sha256
        != imported.candidate_inventory.content_sha256
        or repeated_candidate_export.bytes != imported.candidate_inventory.bytes
        or repeated_candidate_export.relative_path
        != imported.candidate_inventory.relative_path
        or replayed.source_snapshot_hash != imported.source_snapshot_hash
    ):
        raise EvidenceReplayError("bulk replay snapshot or deterministic export changed")

    resource_store = EvidenceResourceStore(isolated)
    with evidence_connection(isolated) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        current_schema_hash = schema_hash(connection)
        resource_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id"
            )
        ]
        orphan_ledgers = int(
            connection.execute(
                """
                SELECT count(*) FROM citation_ledger_entry AS ledger
                LEFT JOIN citation_occurrence AS occurrence USING(citation_id)
                WHERE occurrence.citation_id IS NULL
                """
            ).fetchone()[0]
        )
        orphan_occurrences = int(
            connection.execute(
                """
                SELECT count(*) FROM citation_occurrence AS occurrence
                WHERE NOT EXISTS (
                    SELECT 1 FROM citation_ledger_entry AS ledger
                    WHERE ledger.citation_id=occurrence.citation_id
                )
                """
            ).fetchone()[0]
        )
    if integrity != "ok" or foreign_keys or orphan_ledgers or orphan_occurrences:
        raise EvidenceReplayError("isolated bulk replay failed relational integrity checks")
    for resource_id in resource_ids:
        resource_store.resource_response(resource_id)
    if len(resource_ids) != imported.counts["paper_resource"]:
        raise EvidenceReplayError("bulk resource verification count differs from database")

    release_service = EvidenceReleaseService(isolated)
    prepared = release_service.prepare_candidate()
    authority = ReleaseAuthority(isolated)
    candidate = authority.register_candidate(prepared.candidate_spec)
    decision = authority.record_decision(
        candidate.candidate_id,
        deterministic_gate_hash=stable_sha256(
            "managed-bulk-replay-gate/v1", imported.source_snapshot_hash
        ),
        review_set_hash=stable_sha256(
            "managed-bulk-replay-review/v2",
            imported.inventory.content_sha256,
            imported.candidate_inventory.content_sha256,
        ),
        reconciliation_hash=stable_sha256(
            "managed-bulk-replay-reconciliation/v3",
            "245",
            "5181",
            "4630",
            "18",
            "18-successful-reading-runs",
            "1-controlled-recovery-probe",
        ),
        verdict="pass",
    )
    certificate = authority.issue_snapshot(
        decision.decision_id,
        requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
        issuance_key=stable_sha256(
            "managed-bulk-replay-issuance/v1",
            prepared.candidate_spec.artifact_manifest_hash,
        ),
    )
    published = release_service.publish(prepared, certificate)
    repeated_publish = release_service.publish(prepared, certificate)
    if repeated_publish.created or (
        repeated_publish.activation_id,
        repeated_publish.active_revision,
        repeated_publish.release_snapshot_urn,
    ) != (
        published.activation_id,
        published.active_revision,
        published.release_snapshot_urn,
    ):
        raise EvidenceReplayError("bulk replay release publication is not idempotent")
    return EvidenceReplayResult(
        replay_slug=replay_slug,
        replay_root=target,
        schema_hash=current_schema_hash,
        inventory_sha256=imported.inventory.content_sha256,
        inventory_bytes=imported.inventory.bytes,
        candidate_inventory_sha256=imported.candidate_inventory.content_sha256,
        candidate_inventory_bytes=imported.candidate_inventory.bytes,
        evidence_release_id=prepared.evidence_release_id,
        release_snapshot_urn=certificate.snapshot_urn,
        active_revision=published.active_revision,
        release_created=published.created,
        resource_count=len(resource_ids),
        counts=imported.counts,
    )
