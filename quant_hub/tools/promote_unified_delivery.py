"""把已审核 Evidence 全量包幂等装入统一 Quant Research Hub delivery。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from quant_hub.config import Settings
from quant_hub.evidence.bulk import import_bulk_evidence
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.resources import EvidenceResourceStore
from quant_hub.ids import stable_sha256
from quant_hub.platform.migrations import schema_hash
from quant_hub.platform.releases import ReleaseAuthority


EXPECTED_INVENTORY = "39345ca71611d3d0c391f9675989c469aa5de4c4b225bca92d9650d35c9e0bc2"
EXPECTED_CANDIDATE_INVENTORY = (
    "b8b2f60603c7c0e056b39497ac81bcb07c943444bb92d50da4b002b7a30dc03d"
)
EXPECTED_SCHEMA = "3b6f56ac85836fb86317276422f2a58db26a5d564d82f78016d2be18ee9f3423"


def main() -> int:
    workspace = Path(__file__).resolve().parents[2]
    formal_root = workspace / "quant_hub"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--var-root",
        type=Path,
        default=formal_root / "var" / "delivery",
        help="统一实例运行目录；默认 quant_hub/var/delivery。",
    )
    parser.add_argument(
        "--package",
        type=Path,
        default=workspace / "project_state" / "workers" / "e_evidence_bulk_data",
    )
    parser.add_argument(
        "--normalized-manifest",
        type=Path,
        default=formal_root / "fixtures" / "evidence" / "normalized_resource_manifest.jsonl",
    )
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()

    settings = Settings.default(
        project_root=workspace,
        archive_root=workspace / "reference" / "archive",
        var_root=arguments.var_root.absolute(),
    )
    before_domain_databases = {
        "archive": settings.archive_database_path.stat().st_size
        if settings.archive_database_path.is_file()
        else None,
        "paper_lab": settings.paper_lab_database_path.stat().st_size
        if settings.paper_lab_database_path.is_file()
        else None,
    }
    imported = import_bulk_evidence(
        settings,
        arguments.package.absolute(),
        normalized_manifest_path=arguments.normalized_manifest.absolute(),
    )
    repeated = import_bulk_evidence(
        settings,
        arguments.package.absolute(),
        normalized_manifest_path=arguments.normalized_manifest.absolute(),
    )
    if repeated.created:
        raise RuntimeError("unified delivery Evidence import is not idempotent")
    if imported.inventory.content_sha256 != EXPECTED_INVENTORY:
        raise RuntimeError("unified delivery inventory differs from the reviewed candidate")
    if imported.candidate_inventory.content_sha256 != EXPECTED_CANDIDATE_INVENTORY:
        raise RuntimeError(
            "unified delivery candidate inventory differs from the reviewed candidate"
        )
    if imported.source_snapshot_hash != repeated.source_snapshot_hash:
        raise RuntimeError("unified delivery source snapshot changed on repeat")

    with evidence_connection(settings) as connection:
        actual_schema = schema_hash(connection)
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
        resources = [
            str(row[0])
            for row in connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id"
            )
        ]
    if actual_schema != EXPECTED_SCHEMA:
        raise RuntimeError("unified delivery Evidence schema differs from the reviewed candidate")
    if integrity != "ok" or foreign_keys:
        raise RuntimeError("unified delivery Evidence database integrity check failed")
    store = EvidenceResourceStore(settings)
    for resource_id in resources:
        store.resource_response(resource_id)
    if len(resources) != 18:
        raise RuntimeError("unified delivery must expose exactly 18 verified PDF resources")

    service = EvidenceReleaseService(settings)
    prepared = service.prepare_candidate()
    authority = ReleaseAuthority(settings)
    candidate = authority.register_candidate(prepared.candidate_spec)
    decision = authority.record_decision(
        candidate.candidate_id,
        deterministic_gate_hash=stable_sha256(
            "unified-delivery-evidence-gate/v1",
            prepared.candidate_spec.source_snapshot_hash,
        ),
        review_set_hash=stable_sha256(
            "unified-delivery-evidence-review/v2",
            imported.inventory.content_sha256,
            imported.candidate_inventory.content_sha256,
        ),
        reconciliation_hash=stable_sha256(
            "unified-delivery-evidence-reconciliation/v2",
            "245",
            "5181",
            "4630",
            "18",
        ),
        verdict="pass",
    )
    certificate = authority.issue_snapshot(
        decision.decision_id,
        requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
        issuance_key=stable_sha256(
            "unified-delivery-evidence-issuance/v1",
            prepared.candidate_spec.artifact_manifest_hash,
        ),
    )
    published = service.publish(prepared, certificate)
    after_domain_databases = {
        "archive": settings.archive_database_path.stat().st_size
        if settings.archive_database_path.is_file()
        else None,
        "paper_lab": settings.paper_lab_database_path.stat().st_size
        if settings.paper_lab_database_path.is_file()
        else None,
    }
    if before_domain_databases != after_domain_databases:
        raise RuntimeError("Evidence promotion changed an unrelated domain database")

    payload = {
        "schema_version": "qrh-unified-delivery-promotion/v1",
        "status": "PASS",
        "var_root": str(settings.var_root),
        "import_created": imported.created,
        "repeat_import_created": repeated.created,
        "release_created": published.created,
        "counts": imported.counts,
        "schema_sha256": actual_schema,
        "inventory_sha256": imported.inventory.content_sha256,
        "candidate_inventory_sha256": imported.candidate_inventory.content_sha256,
        "source_snapshot_hash": prepared.candidate_spec.source_snapshot_hash,
        "artifact_manifest_hash": prepared.candidate_spec.artifact_manifest_hash,
        "requirements_manifest_hash": prepared.candidate_spec.requirements_manifest_hash,
        "evidence_release_id": prepared.evidence_release_id,
        "release_snapshot_urn": certificate.snapshot_urn,
        "activation_id": published.activation_id,
        "active_revision": published.active_revision,
        "verified_resource_count": len(resources),
        "unrelated_domain_database_sizes": after_domain_databases,
    }
    rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if arguments.report is not None:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
