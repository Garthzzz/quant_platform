from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sqlite3

from quant_hub.config import Settings, ensure_no_reparse_components
from quant_hub.evidence.bulk import import_bulk_evidence
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.resources import EvidenceResourceStore
from quant_hub.ids import stable_sha256
from quant_hub.platform.migrations import schema_hash
from quant_hub.platform.releases import ReleaseAuthority


_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _quiesce_database(path: Path) -> None:
    """在离线候选交付末尾 checkpoint WAL，并切回无 sidecar 的 DELETE。"""

    connection = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    try:
        connection.execute("PRAGMA busy_timeout=10000")
        checkpoint = tuple(connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())
        if checkpoint[0] != 0:
            raise RuntimeError(f"delivery database WAL checkpoint remained busy: {path}")
        mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
        if mode.casefold() != "delete":
            raise RuntimeError(f"delivery database could not leave WAL mode: {path}")
        if str(connection.execute("PRAGMA integrity_check").fetchone()[0]) != "ok":
            raise RuntimeError(f"delivery database failed post-release integrity check: {path}")
    finally:
        connection.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise RuntimeError(f"delivery database retains a non-empty sidecar: {sidecar}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="将已复核的 Archive Evidence 全量包幂等提升到 var/delivery。"
    )
    parser.add_argument("delivery_slug")
    parser.add_argument("--expected-inventory-sha256", required=True)
    parser.add_argument("--expected-candidate-inventory-sha256", required=True)
    parser.add_argument("--expected-schema-sha256", required=True)
    parser.add_argument(
        "--package",
        type=Path,
        default=Path("project_state/workers/e_evidence_bulk_data"),
    )
    parser.add_argument(
        "--normalized-manifest",
        type=Path,
        default=Path("quant_hub/fixtures/evidence/normalized_resource_manifest.jsonl"),
    )
    arguments = parser.parse_args()
    if not _SLUG.fullmatch(arguments.delivery_slug):
        raise ValueError("delivery slug is unsafe")
    if not _HASH.fullmatch(arguments.expected_inventory_sha256):
        raise ValueError("expected inventory hash is invalid")
    if not _HASH.fullmatch(arguments.expected_candidate_inventory_sha256):
        raise ValueError("expected candidate inventory hash is invalid")
    if not _HASH.fullmatch(arguments.expected_schema_sha256):
        raise ValueError("expected schema hash is invalid")

    base = Settings.default(project_root=Path.cwd())
    delivery_parent = base.var_root / "delivery" / "evidence"
    target = delivery_parent / arguments.delivery_slug
    ensure_no_reparse_components(delivery_parent)
    ensure_no_reparse_components(target)
    if target.parent != delivery_parent:
        raise ValueError("delivery target must be a direct child")
    settings = Settings(
        project_root=base.project_root,
        archive_root=base.archive_root,
        var_root=target,
        database_path=target / "db" / "platform.sqlite3",
        object_root=target / "objects",
        migration_root=base.migration_root,
    )
    settings.validate()

    imported = import_bulk_evidence(
        settings,
        arguments.package,
        normalized_manifest_path=arguments.normalized_manifest,
    )
    repeated = import_bulk_evidence(
        settings,
        arguments.package,
        normalized_manifest_path=arguments.normalized_manifest,
    )
    if repeated.created:
        raise RuntimeError("delivery import is not idempotent")
    if imported.inventory.content_sha256 != arguments.expected_inventory_sha256:
        raise RuntimeError("delivery inventory differs from reviewed replay")
    if (
        imported.candidate_inventory.content_sha256
        != arguments.expected_candidate_inventory_sha256
    ):
        raise RuntimeError("delivery candidate inventory differs from reviewed replay")
    if repeated.source_snapshot_hash != imported.source_snapshot_hash:
        raise RuntimeError("delivery source snapshot changed on repeat")

    with evidence_connection(settings) as connection:
        actual_schema_hash = schema_hash(connection)
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        resource_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id"
            )
        ]
    if actual_schema_hash != arguments.expected_schema_sha256:
        raise RuntimeError("delivery schema differs from reviewed replay")
    if integrity != "ok" or foreign_keys:
        raise RuntimeError("delivery database integrity checks failed")
    store = EvidenceResourceStore(settings)
    for resource_id in resource_ids:
        store.resource_response(resource_id)
    if len(resource_ids) != 18:
        raise RuntimeError("delivery must contain exactly 18 verified PDF resources")

    service = EvidenceReleaseService(settings)
    prepared = service.prepare_candidate()
    authority = ReleaseAuthority(settings)
    candidate = authority.register_candidate(prepared.candidate_spec)
    decision = authority.record_decision(
        candidate.candidate_id,
        deterministic_gate_hash=stable_sha256(
            "formal-evidence-delivery-gate/v1",
            prepared.candidate_spec.source_snapshot_hash,
        ),
        review_set_hash=stable_sha256(
            "formal-evidence-delivery-review/v2",
            prepared.inventory.content_sha256,
            prepared.candidate_inventory.content_sha256,
        ),
        reconciliation_hash=stable_sha256(
            "formal-evidence-delivery-reconciliation/v2", "245", "5181", "4630", "18"
        ),
        verdict="pass",
    )
    certificate = authority.issue_snapshot(
        decision.decision_id,
        requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
        issuance_key=stable_sha256(
            "formal-evidence-delivery-issuance/v1",
            prepared.candidate_spec.artifact_manifest_hash,
        ),
    )
    published = service.publish(prepared, certificate)
    _quiesce_database(settings.research_papers_database_path)
    _quiesce_database(settings.database_path)
    print(
        json.dumps(
            {
                "delivery_root": str(target),
                "import_created": imported.created,
                "release_created": published.created,
                "counts": imported.counts,
                "schema_sha256": actual_schema_hash,
                "inventory_sha256": imported.inventory.content_sha256,
                "candidate_inventory_sha256": (
                    imported.candidate_inventory.content_sha256
                ),
                "source_snapshot_hash": prepared.candidate_spec.source_snapshot_hash,
                "artifact_manifest_hash": prepared.candidate_spec.artifact_manifest_hash,
                "requirements_manifest_hash": prepared.candidate_spec.requirements_manifest_hash,
                "evidence_release_id": prepared.evidence_release_id,
                "release_snapshot_urn": certificate.snapshot_urn,
                "activation_id": published.activation_id,
                "active_revision": published.active_revision,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
