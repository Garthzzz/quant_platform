"""在隔离 var 中对真实只读 Archive 代表集执行 B 纵切回放。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from quant_hub.archive.catalog import ArchiveCatalog, PublishedArchiveRelease
from quant_hub.archive.contracts import ActorInput, ArchiveReleaseInput, TopicInput
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.config import Settings
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import ReleaseAuthority, ReleaseCandidateSpec


ROOT = Path(__file__).resolve().parents[2]
FORMAL_ROOT = ROOT / "quant_hub"
FIXTURE_ROOT = FORMAL_ROOT / "fixtures" / "archive_b"
Q2_V2_SHA = "5b2e4fcb3bfbe8024df59fcd9370ed641fa8919cfce1ffea7493e1f6a7a8fd03"
Q2_V3_SHA = "e68a63a1883c24cf48de6d4b3f0a9030689feced99e02ea4ed9f33144ed4dc7a"


def source_snapshot(root: Path) -> dict[str, object]:
    rows: list[tuple[str, int, str]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        payload = path.read_bytes()
        rows.append((path.relative_to(root).as_posix(), len(payload), hashlib.sha256(payload).hexdigest()))
    aggregate = hashlib.sha256(
        "\n".join(f"{name}\t{size}\t{digest}" for name, size, digest in rows).encode("utf-8")
    ).hexdigest()
    return {
        "paths": len(rows),
        "bytes": sum(row[1] for row in rows),
        "aggregate_sha256": aggregate,
        "rows": rows,
    }


def load_release(name: str) -> ArchiveReleaseInput:
    return ArchiveReleaseInput.model_validate(
        json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    )


def existing_release(
    settings: Settings,
    research_slug: str,
    content_sha256: str,
) -> PublishedArchiveRelease | None:
    with archive_connection(settings) as connection:
        row = connection.execute(
            """
            SELECT research.research_id,release.research_release_id,
                   release.document_manifest_hash,active.activation_id,active.revision,
                   identity.subject_urn,identity.subject_version_urn,
                   identity.source_snapshot_hash,identity.projection_revision,
                   identity.requirements_manifest_hash
            FROM research
            JOIN research_release AS release USING(research_id)
            JOIN research_release_candidate_identity AS identity USING(research_release_id)
            JOIN research_release_item AS item USING(research_release_id)
            JOIN research_document_version AS version USING(document_version_id)
            LEFT JOIN active_research_release AS active
              ON active.research_id=research.research_id
             AND active.research_release_id=release.research_release_id
            WHERE research.canonical_slug=? AND version.content_sha256=?
            ORDER BY release.created_at LIMIT 1
            """,
            (research_slug, content_sha256),
        ).fetchone()
        if row is None:
            return None
        versions = connection.execute(
            "SELECT document_version_id FROM research_release_item WHERE research_release_id=? ORDER BY sort_key,document_id",
            (row["research_release_id"],),
        ).fetchall()
    return PublishedArchiveRelease(
        research_id=str(row["research_id"]),
        research_release_id=str(row["research_release_id"]),
        activation_id=str(row["activation_id"]) if row["activation_id"] else None,
        active_revision=int(row["revision"]) if row["revision"] else None,
        document_version_ids=tuple(str(item["document_version_id"]) for item in versions),
        document_manifest_hash=str(row["document_manifest_hash"]),
        candidate_spec=ReleaseCandidateSpec(
            domain="archive",
            subject_urn=str(row["subject_urn"]),
            subject_version_urn=str(row["subject_version_urn"]),
            artifact_manifest_hash=str(row["document_manifest_hash"]),
            source_snapshot_hash=str(row["source_snapshot_hash"]),
            projection_revision=str(row["projection_revision"]),
            requirements_manifest_hash=str(row["requirements_manifest_hash"]),
        ),
        created=False,
    )


def approve_and_publish(
    catalog: ArchiveCatalog,
    authority: ReleaseAuthority,
    release: ArchiveReleaseInput,
    *,
    fixture_name: str,
) -> PublishedArchiveRelease:
    if release.activate:
        raise RuntimeError("B fixture must be an unsigned candidate manifest")
    spec = catalog.prepare_release_candidate(release)
    fixture_hash = hashlib.sha256((FIXTURE_ROOT / fixture_name).read_bytes()).hexdigest()
    candidate = authority.register_candidate(spec)
    decision = authority.record_decision(
        candidate.candidate_id,
        deterministic_gate_hash=stable_sha256(
            "archive-b-deterministic-gate/v1",
            fixture_hash,
            spec.artifact_manifest_hash,
            spec.source_snapshot_hash,
            spec.projection_revision,
        ),
        review_set_hash=stable_sha256(
            "archive-b-review-set/v1",
            fixture_hash,
            "project_state/workers/b_fixture_selection/artifact_manifest.sha256",
        ),
        reconciliation_hash=stable_sha256(
            "archive-b-reconciliation/v1",
            spec.requirements_manifest_hash,
            fixture_hash,
        ),
        verdict="pass",
    )
    certificate = authority.issue_snapshot(
        decision.decision_id,
        requirements_manifest_hash=spec.requirements_manifest_hash,
        issuance_key=stable_sha256(
            "archive-b-release-issuance/v1", fixture_name, fixture_hash
        ),
    )
    approved = release.model_copy(
        update={
            "activate": True,
            "release_snapshot_urn": certificate.snapshot_urn,
            "activation_decision_hash": certificate.decision_hash,
        }
    )
    return catalog.publish_release(approved)


def require_ok(outcome: object, label: str) -> dict[str, object]:
    if not getattr(outcome, "ok", False):
        raise RuntimeError(
            f"{label} failed: {getattr(outcome, 'error_code', None)} "
            f"{getattr(outcome, 'error_message', None)}"
        )
    return dict(getattr(outcome, "data"))


def run(settings: Settings) -> dict[str, object]:
    before = source_snapshot(settings.archive_root)
    catalog = ArchiveCatalog(settings)
    collaboration = ArchiveCollaboration(settings)
    catalog.initialize()
    authority = ReleaseAuthority(settings)
    reviewer = ActorInput(actor_kind="zhang_zhengze")
    transitions: list[dict[str, object]] = []

    q2_v2 = existing_release(settings, "q2-low-snr-neural-selection-factory", Q2_V2_SHA)
    if q2_v2 is None:
        q2_v2 = approve_and_publish(
            catalog, authority, load_release("q2-v2.json"), fixture_name="q2-v2.json"
        )
    q2_topic = require_ok(
        collaboration.create_topic(
            TopicInput(topic_key="q2-training-factory", title="Q2：如何造一个好的工厂", manual_order=20),
            reviewer,
            idempotency_key="b-fixture-topic-q2-v1",
        ),
        "create Q2 topic",
    )
    q2_topic_id = str(q2_topic["topic_id"])
    require_ok(
        collaboration.link_topic_research(
            q2_topic_id,
            q2_v2.research_id,
            reviewer,
            link_kind="primary",
            dashboard_primary=True,
            display_rank=10,
            provenance_urn="qrh:review:b-fixture-topic-link-v1",
            idempotency_key="b-fixture-link-q2-v1",
        ),
        "link Q2 topic",
    )
    require_ok(
        collaboration.complete_research(
            q2_v2.research_id,
            q2_v2.research_release_id,
            reason="B 独立夹具只确认 v2 文献综述定义范围完成，不扩张到实验验证。",
            actor=reviewer,
            idempotency_key="b-fixture-complete-q2-v2",
        ),
        "complete Q2 v2",
    )
    q2_state_v2 = next(row for row in collaboration.dashboard() if row["topic_id"] == q2_topic_id)
    if q2_state_v2["state"] != "completed":
        raise RuntimeError("Q2 v2 explicit completion did not project to Dashboard")
    transitions.append({"stage": "q2_v2_explicit_completion", "state": "completed"})

    with archive_connection(settings) as connection:
        v3_completion_receipt_exists = connection.execute(
            "SELECT 1 FROM command_receipt WHERE idempotency_key='b-fixture-complete-q2-v3'"
        ).fetchone() is not None
    q2_v3 = approve_and_publish(
        catalog, authority, load_release("q2-v3.json"), fixture_name="q2-v3.json"
    )
    if not v3_completion_receipt_exists:
        q2_state_after_activation = next(
            row for row in collaboration.dashboard() if row["topic_id"] == q2_topic_id
        )
        if q2_state_after_activation["state"] != "planned":
            raise RuntimeError("v2 completion was incorrectly inherited by active v3")
        transitions.append(
            {"stage": "q2_v3_activated_before_decision", "state": "planned", "old_completion_inherited": False}
        )
    require_ok(
        collaboration.complete_research(
            q2_v3.research_id,
            q2_v3.research_release_id,
            reason="B 独立夹具确认当前 v3 文献综述定义范围完成；实验验证仍未完成。",
            actor=reviewer,
            idempotency_key="b-fixture-complete-q2-v3",
        ),
        "complete Q2 v3",
    )
    transitions.append({"stage": "q2_v3_explicit_completion", "state": "completed"})

    q4 = approve_and_publish(
        catalog, authority, load_release("q4.json"), fixture_name="q4.json"
    )
    q4_topic = require_ok(
        collaboration.create_topic(
            TopicInput(topic_key="q4-operations-monitoring", title="Q4：实操与部署后监测", manual_order=40),
            reviewer,
            idempotency_key="b-fixture-topic-q4-v1",
        ),
        "create Q4 topic",
    )
    q4_topic_id = str(q4_topic["topic_id"])
    require_ok(
        collaboration.link_topic_research(
            q4_topic_id,
            q4.research_id,
            reviewer,
            link_kind="primary",
            dashboard_primary=True,
            display_rank=10,
            provenance_urn="qrh:review:b-fixture-topic-link-v1",
            idempotency_key="b-fixture-link-q4-v1",
        ),
        "link Q4 topic",
    )
    require_ok(
        collaboration.set_work_state(
            q4.research_id,
            "paused",
            "正式归类和权威定义核对尚未完成。",
            reviewer,
            idempotency_key="b-fixture-work-q4-paused-v1",
        ),
        "pause Q4 research",
    )
    require_ok(
        collaboration.set_topic_state(
            q4_topic_id,
            "paused",
            "正式归类和权威定义核对尚未完成。",
            reviewer,
            idempotency_key="b-fixture-topic-q4-paused-v1",
        ),
        "pause Q4 topic",
    )

    experiments = approve_and_publish(
        catalog,
        authority,
        load_release("experiments.json"),
        fixture_name="experiments.json",
    )
    exp_topic = require_ok(
        collaboration.create_topic(
            TopicInput(topic_key="experiments-e1-e8", title="Experiments：E1–E8", manual_order=50),
            reviewer,
            idempotency_key="b-fixture-topic-experiments-v1",
        ),
        "create experiments topic",
    )
    exp_topic_id = str(exp_topic["topic_id"])
    require_ok(
        collaboration.link_topic_research(
            exp_topic_id,
            experiments.research_id,
            reviewer,
            link_kind="primary",
            dashboard_primary=True,
            display_rank=10,
            provenance_urn="qrh:review:b-fixture-topic-link-v1",
            idempotency_key="b-fixture-link-experiments-v1",
        ),
        "link experiments topic",
    )
    require_ok(
        collaboration.set_topic_state(
            exp_topic_id,
            "planned",
            "E1–E8 实验档与结果整合仍待执行。",
            reviewer,
            idempotency_key="b-fixture-topic-experiments-planned-v1",
        ),
        "plan experiments topic",
    )

    require_ok(
        collaboration.create_comment(
            q2_v3.research_id,
            ActorInput(actor_kind="other", display_name="纵切审核员"),
            "B 纵切回放评论：正文、派生页面与评论存储保持分离。",
            idempotency_key="b-fixture-comment-q2-v1",
        ),
        "create persistent comment",
    )

    dashboard = collaboration.dashboard()
    states = {row["topic_key"]: row["state"] for row in dashboard}
    expected_states = {
        "q2-training-factory": "completed",
        "q4-operations-monitoring": "paused",
        "experiments-e1-e8": "planned",
    }
    if states != expected_states:
        raise RuntimeError(f"Dashboard state mismatch: {states!r}")
    page = catalog.research_page(q2_v3.research_id)
    main = next(item for item in page["documents"] if item["slug"] == "literature-review")
    if len(main["sections"]) != 132 or 'class="table-scroll"' not in main["rendered_html"]:
        raise RuntimeError("Q2 v3 long-form projection is incomplete")
    source_bytes, _ = catalog.source_document(q2_v3.research_id, main["document_id"])
    expected_source = (
        settings.archive_root
        / "Q2_如何造一个好的工厂"
        / "RESEARCH_LITREVIEW_AND_ANALYSIS_DETAILED.md"
    ).read_bytes()
    if source_bytes != expected_source or hashlib.sha256(source_bytes).hexdigest() != Q2_V3_SHA:
        raise RuntimeError("active page source route does not resolve exact Archive bytes")
    searches = {
        query: len(catalog.search(query))
        for query in ("低信噪比", "部署后监测", "E1")
    }
    if any(count < 1 for count in searches.values()):
        raise RuntimeError(f"representative search failed: {searches!r}")
    comments = collaboration.list_comments(q2_v3.research_id)
    if len(comments) != 1 or comments[0]["actor"]["display_name"] != "纵切审核员":
        raise RuntimeError("persistent comment replay is incomplete")

    with archive_connection(settings) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        counts = {
            name: int(connection.execute(f"SELECT count(*) FROM {name}").fetchone()[0])
            for name in (
                "research", "research_document", "research_document_version",
                "research_release", "research_release_activation", "outline_node",
                "comment", "topic", "command_receipt", "outbox_event",
            )
        }
    after = source_snapshot(settings.archive_root)
    if before != after:
        raise RuntimeError("Archive source tree changed during B replay")
    return {
        "schema_version": "qrh-archive-b-replay/v1",
        "status": "PASS",
        "source_integrity": {
            "paths": before["paths"],
            "bytes": before["bytes"],
            "aggregate_sha256": before["aggregate_sha256"],
            "changed": 0,
        },
        "transitions": transitions,
        "dashboard_states": states,
        "search_result_counts": searches,
        "long_form": {
            "sha256": Q2_V3_SHA,
            "bytes": len(source_bytes),
            "headings": len(main["sections"]),
            "table_scroll": True,
        },
        "comments": len(comments),
        "database": {"integrity_check": integrity, "foreign_key_violations": foreign_keys, "counts": counts},
        "research_ids": {"q2": q2_v3.research_id, "q4": q4.research_id, "experiments": experiments.research_id},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument("--archive-root", type=Path)
    parser.add_argument("--var-root", type=Path, required=True)
    args = parser.parse_args()
    settings = Settings.default(
        project_root=args.project_root,
        archive_root=args.archive_root,
        var_root=args.var_root,
    )
    print(json.dumps(run(settings), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
