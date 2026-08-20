"""消费独立 PASS 映射审核，在受管 var 中发布全量 Archive 并回放状态。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import ActorInput, ArchiveReleaseInput, TopicInput
from quant_hub.archive.database import archive_connection
from quant_hub.archive.discovery import ArchiveDiscoveryScanner
from quant_hub.collaboration.service import (
    ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH,
    ArchiveCollaboration,
)
from quant_hub.config import Settings
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.platform.reviews import ReviewAuthority, ReviewCertificateSpec


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
GENERATED_ROOT = FORMAL_ROOT / "fixtures" / "archive_full" / "generated"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_generated_release(relative_path: str) -> ArchiveReleaseInput:
    """Load a reviewed release whose path is relative to GENERATED_ROOT."""

    return ArchiveReleaseInput.model_validate_json(
        (GENERATED_ROOT / relative_path).read_bytes()
    )


def load_workspace_release(relative_path: str) -> ArchiveReleaseInput:
    """Load a reviewed bootstrap release whose path is relative to WORKSPACE_ROOT."""

    return ArchiveReleaseInput.model_validate_json(
        (WORKSPACE_ROOT / relative_path).read_bytes()
    )


def source_snapshot(root: Path) -> dict[str, Any]:
    rows: list[tuple[str, int, str]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        payload = path.read_bytes()
        rows.append(
            (
                path.relative_to(root).as_posix(),
                len(payload),
                hashlib.sha256(payload).hexdigest(),
            )
        )
    aggregate = hashlib.sha256(
        "\n".join(f"{name}\t{size}\t{digest}" for name, size, digest in rows).encode("utf-8")
    ).hexdigest()
    return {
        "files": len(rows),
        "bytes": sum(row[1] for row in rows),
        "aggregate_sha256": aggregate,
    }


def load_review(path: Path, index: dict[str, Any]) -> tuple[dict[str, Any], str]:
    payload = path.read_bytes()
    review = json.loads(payload.decode("utf-8"))
    if review.get("schema_version") != "qrh-archive-full-mapping-review/v1":
        raise ValueError("mapping review schema is not supported")
    if review.get("status") != "PASS" or review.get("p0") or review.get("p1"):
        raise ValueError("mapping review does not contain a clean PASS")
    index_hash = sha256_file(GENERATED_ROOT / "index.json")
    if review.get("candidate_index_sha256") != index_hash:
        raise ValueError("mapping review is stale for the current candidate index")
    if review.get("policy_sha256") != index["policy_sha256"]:
        raise ValueError("mapping review policy hash does not match")
    expected_releases = {
        row["research_slug"]: row["release_sha256"] for row in index["groups"]
    }
    expected_releases.update(
        {
            f"bootstrap:{row['release_key']}": row["sha256"]
            for row in index.get("bootstrap_releases", [])
        }
    )
    if review.get("release_hashes") != expected_releases:
        raise ValueError("mapping review release set does not match")
    for field in ("reviewer_identity_hash", "review_set_hash"):
        value = review.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError(f"mapping review {field} is not canonical")
    approvals = review.get("completion_approvals")
    if not isinstance(approvals, list):
        raise ValueError("mapping review completion approvals are missing")
    valid_slugs = {row["research_slug"] for row in index["groups"]}
    seen: set[str] = set()
    for approval in approvals:
        slug = approval.get("research_slug")
        if slug not in valid_slugs or slug in seen:
            raise ValueError("mapping review has invalid completion approval identity")
        seen.add(slug)
        if approval.get("approved") is not True:
            raise ValueError("completion_approvals may only contain explicit approvals")
        if not str(approval.get("reason", "")).strip() or not approval.get("evidence_locators"):
            raise ValueError("completion approval requires reason and evidence locators")
    return review, hashlib.sha256(payload).hexdigest()


def require_ok(outcome: Any, label: str) -> dict[str, Any]:
    if not outcome.ok:
        raise RuntimeError(
            f"{label}: {outcome.error_code or outcome.status}: {outcome.error_message}"
        )
    return dict(outcome.data or {})


def approve_and_publish(
    catalog: ArchiveCatalog,
    authority: ReleaseAuthority,
    release: ArchiveReleaseInput,
    *,
    release_file_hash: str,
    review_hash: str,
    policy_hash: str,
):
    spec = catalog.prepare_release_candidate(release)
    candidate = authority.register_candidate(spec)
    decision = authority.record_decision(
        candidate.candidate_id,
        deterministic_gate_hash=stable_sha256(
            "archive-full-deterministic-gate/v1",
            release_file_hash,
            spec.artifact_manifest_hash,
            spec.source_snapshot_hash,
        ),
        review_set_hash=review_hash,
        reconciliation_hash=stable_sha256(
            "archive-full-reconciliation/v1",
            policy_hash,
            spec.requirements_manifest_hash,
        ),
        verdict="pass",
    )
    certificate = authority.issue_snapshot(
        decision.decision_id,
        requirements_manifest_hash=spec.requirements_manifest_hash,
        issuance_key=stable_sha256(
            "archive-full-release-issuance/v1",
            release.research_slug,
            release_file_hash,
            review_hash,
        ),
    )
    return catalog.publish_release(
        release.model_copy(
            update={
                "activate": True,
                "release_snapshot_urn": certificate.snapshot_urn,
                "activation_decision_hash": certificate.decision_hash,
            }
        )
    )


def existing_topic(settings: Settings, topic_key: str) -> dict[str, Any] | None:
    with archive_connection(settings) as connection:
        row = connection.execute(
            "SELECT topic_id,topic_key,title,manual_order FROM topic WHERE topic_key=?",
            (topic_key,),
        ).fetchone()
    return dict(row) if row is not None else None


def already_published(
    settings: Settings,
    authority: ReleaseAuthority,
    catalog: ArchiveCatalog,
    release: ArchiveReleaseInput,
) -> bool:
    """识别已消费同一证书的历史 release，避免重跑时倒退活动指针。"""

    spec = catalog.prepare_release_candidate(release)
    with archive_connection(settings) as connection:
        row = connection.execute(
            """
            SELECT identity.subject_urn,identity.subject_version_urn,
                   identity.artifact_manifest_hash,identity.source_snapshot_hash,
                   identity.requirements_manifest_hash,identity.projection_revision,
                   consumption.release_snapshot_urn,consumption.decision_hash
            FROM research_release_candidate_identity AS identity
            JOIN research_release_authority_consumption AS consumption
              USING(research_release_id)
            WHERE identity.subject_version_urn=?
            """,
            (spec.subject_version_urn,),
        ).fetchone()
    if row is None:
        return False
    actual = (
        str(row["subject_urn"]),
        str(row["subject_version_urn"]),
        str(row["artifact_manifest_hash"]),
        str(row["source_snapshot_hash"]),
        str(row["requirements_manifest_hash"]),
        str(row["projection_revision"]),
    )
    expected = (
        spec.subject_urn,
        spec.subject_version_urn,
        spec.artifact_manifest_hash,
        spec.source_snapshot_hash,
        spec.requirements_manifest_hash,
        spec.projection_revision,
    )
    if actual != expected:
        raise RuntimeError("existing historical release conflicts with current frozen material")
    authority.verify_snapshot(
        str(row["release_snapshot_urn"]),
        str(row["decision_hash"]),
        spec,
    )
    return True


def run(
    settings: Settings,
    review_path: Path,
    *,
    research_slugs: frozenset[str] | None = None,
) -> dict[str, Any]:
    before = source_snapshot(settings.archive_root)
    index = json.loads((GENERATED_ROOT / "index.json").read_text(encoding="utf-8"))
    review, review_hash = load_review(review_path, index)
    approvals = {
        row["research_slug"]: row for row in review["completion_approvals"]
    }
    discovery_before = ArchiveDiscoveryScanner(settings).scan()
    current_paths = {
        str(document.source_path)
        for group in index["groups"]
        for document in load_generated_release(str(group["release_file"])).documents
    }
    historical_paths = {
        str(document.source_path)
        for item in index["bootstrap_releases"]
        for document in load_workspace_release(str(item["path"])).documents
        if str(document.source_path) not in current_paths
        and (settings.archive_root / str(document.source_path)).is_file()
    }
    expected_markdown = int(index["source"]["markdown_count"]) + len(
        historical_paths
    )
    if (
        discovery_before.status != "PASS"
        or discovery_before.counts.markdown_candidates != expected_markdown
    ):
        raise RuntimeError(
            "full Archive discovery did not match the reviewed source snapshot: "
            f"expected {expected_markdown}, got "
            f"{discovery_before.counts.markdown_candidates}"
        )

    catalog = ArchiveCatalog(settings)
    collaboration = ArchiveCollaboration(settings)
    release_authority = ReleaseAuthority(settings)
    review_authority = ReviewAuthority(settings)
    importer = ActorInput(actor_kind="other", display_name="Archive 全量导入器")
    published_rows: list[dict[str, Any]] = []

    known_slugs = {str(group["research_slug"]) for group in index["groups"]}
    unknown_slugs = set(research_slugs or ()) - known_slugs
    if unknown_slugs:
        raise ValueError(f"unknown reviewed research slug(s): {sorted(unknown_slugs)}")

    for bootstrap in index.get("bootstrap_releases", []) if research_slugs is None else []:
        bootstrap_path = WORKSPACE_ROOT / str(bootstrap["path"])
        if sha256_file(bootstrap_path) != bootstrap["sha256"]:
            raise RuntimeError("bootstrap release changed after mapping review")
        bootstrap_release = ArchiveReleaseInput.model_validate_json(
            bootstrap_path.read_bytes()
        )
        if not already_published(
            settings,
            release_authority,
            catalog,
            bootstrap_release,
        ):
            approve_and_publish(
                catalog,
                release_authority,
                bootstrap_release,
                release_file_hash=str(bootstrap["sha256"]),
                review_hash=review_hash,
                policy_hash=index["policy_sha256"],
            )

    for group in index["groups"]:
        if research_slugs is not None and str(group["research_slug"]) not in research_slugs:
            continue
        release_path = GENERATED_ROOT / group["release_file"]
        release_hash = sha256_file(release_path)
        release = ArchiveReleaseInput.model_validate_json(release_path.read_bytes())
        published = approve_and_publish(
            catalog,
            release_authority,
            release,
            release_file_hash=release_hash,
            review_hash=review_hash,
            policy_hash=index["policy_sha256"],
        )
        state_hint = str(group["work_state_hint"])
        approval = approvals.get(release.research_slug)
        if approval is not None:
            certificate = review_authority.issue_pass_certificate(
                ReviewCertificateSpec(
                    gate_name="archive_research_completion",
                    gate_version="1",
                    subject_urn=published.candidate_spec.subject_urn,
                    subject_version_urn=published.candidate_spec.subject_version_urn,
                    artifact_manifest_hash=published.candidate_spec.artifact_manifest_hash,
                    requirements_manifest_hash=(
                        ARCHIVE_COMPLETION_REVIEW_REQUIREMENTS_HASH
                    ),
                    review_artifact_hash=review_hash,
                    review_set_hash=str(review["review_set_hash"]),
                    reviewer_identity_hash=str(review["reviewer_identity_hash"]),
                ),
                issuance_key=stable_sha256(
                    "archive-full-completion-certificate/v1",
                    release.research_slug,
                    published.candidate_spec.subject_version_urn,
                    review_hash,
                ),
            )
            require_ok(
                collaboration.complete_research(
                    published.research_id,
                    published.research_release_id,
                    reason=str(approval["reason"]),
                    review_urn=certificate.certificate_urn,
                    idempotency_key=stable_sha256(
                        "archive-full-completion-command/v1",
                        release.research_slug,
                        review_hash,
                    ),
                ),
                f"complete {release.research_slug}",
            )
            effective_state = "completed"
        else:
            effective_state = (
                "in_progress" if state_hint == "completed_candidate" else state_hint
            )
            require_ok(
                collaboration.set_work_state(
                    published.research_id,
                    effective_state,
                    str(group["work_state_reason"]),
                    importer,
                    idempotency_key=stable_sha256(
                        "archive-full-work-state/v1",
                        release.research_slug,
                        effective_state,
                        review_hash,
                    ),
                ),
                f"set work state {release.research_slug}",
            )

        topic_key = group.get("dashboard_topic_key")
        # 已完成 topic 由有效 completion decision 自动进入 Dashboard；计划中和
        # 暂停 topic 必须由研究员显式创建/维护，导入器不得替他们预填。
        if topic_key and effective_state == "completed":
            topic_outcome = collaboration.create_topic(
                TopicInput(
                    topic_key=str(topic_key),
                    title=release.display_title,
                    manual_order=int(group["dashboard_order"]),
                ),
                importer,
                idempotency_key=stable_sha256(
                    "archive-full-topic-create/v1", str(topic_key), review_hash
                ),
            )
            if topic_outcome.ok:
                topic_id = str((topic_outcome.data or {})["topic_id"])
            elif topic_outcome.error_code == "topic_key_conflict":
                topic = existing_topic(settings, str(topic_key))
                if topic is None or topic["title"] != release.display_title:
                    raise RuntimeError(f"existing topic conflicts: {topic_key}")
                topic_id = str(topic["topic_id"])
            else:
                require_ok(topic_outcome, f"create topic {topic_key}")
                raise AssertionError("unreachable")
            require_ok(
                collaboration.link_topic_research(
                    topic_id,
                    published.research_id,
                    importer,
                    link_kind="primary",
                    dashboard_primary=True,
                    display_rank=10,
                    provenance_urn="qrh:review:archive-full-mapping-v1",
                    idempotency_key=stable_sha256(
                        "archive-full-topic-link/v1",
                        str(topic_key),
                        release.research_slug,
                        review_hash,
                    ),
                ),
                f"link topic {topic_key}",
            )
        published_rows.append(
            {
                "research_slug": release.research_slug,
                "research_id": published.research_id,
                "research_release_id": published.research_release_id,
                "documents": len(published.document_version_ids),
                "state": effective_state,
            }
        )

    dashboard = collaboration.dashboard()
    link_index = catalog.archive_link_index()
    if not link_index:
        raise RuntimeError("active Archive link index is empty after replay")
    discovery_after = ArchiveDiscoveryScanner(settings).scan()
    expected_unmapped = int(index["coverage"]["excluded_count"]) + int(
        index["coverage"]["unassigned_count"]
    )
    expected_mapped = expected_markdown - expected_unmapped
    if (
        discovery_after.status != "PASS"
        or discovery_after.counts.markdown_candidates != expected_markdown
        or discovery_after.counts.mapped != expected_mapped
        or discovery_after.counts.unmapped != expected_unmapped
        or discovery_after.counts.pending_mapping != expected_unmapped
        or discovery_after.counts.errors != 0
    ):
        raise RuntimeError("post-publish Archive discovery coverage is incomplete")
    after = source_snapshot(settings.archive_root)
    if before != after:
        raise RuntimeError("Archive source changed during full replay")
    with archive_connection(settings) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "research",
                "research_document",
                "research_document_version",
                "research_release",
                "research_release_activation",
                "research_completion_decision",
                "research_completion_review_consumption",
                "topic",
                "outbox_event",
            )
        }
    return {
        "schema_version": "qrh-archive-full-replay/v1",
        "status": "PASS",
        "mapping_review_sha256": review_hash,
        "source_integrity": {**before, "changed": 0},
        "discovery": discovery_after.to_dict(),
        "discovery_before": discovery_before.to_dict(),
        "discovery_after": discovery_after.to_dict(),
        "published": published_rows,
        "dashboard": dashboard,
        "database": {
            "integrity_check": integrity,
            "foreign_key_violations": foreign_keys,
            "counts": counts,
        },
    }


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=WORKSPACE_ROOT)
    parser.add_argument("--archive-root", type=Path)
    parser.add_argument("--var-root", type=Path, required=True)
    parser.add_argument("--review-verdict", type=Path, required=True)
    parser.add_argument(
        "--research-slug",
        action="append",
        default=[],
        help="只回放经同一 verdict 审核的指定 research；可重复。省略时执行全量回放。",
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    settings = Settings.default(
        project_root=args.project_root,
        archive_root=args.archive_root,
        var_root=args.var_root,
    )
    serialized = json.dumps(
        run(
            settings,
            args.review_verdict.resolve(),
            research_slugs=(
                frozenset(str(value) for value in args.research_slug)
                if args.research_slug
                else None
            ),
        ),
        ensure_ascii=False,
        sort_keys=True,
    )
    if args.report is not None:
        report_path = args.report.resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = report_path.with_name(report_path.name + ".tmp")
        temporary.write_text(serialized + "\n", encoding="utf-8", newline="\n")
        temporary.replace(report_path)
    print(serialized)


if __name__ == "__main__":
    main()
