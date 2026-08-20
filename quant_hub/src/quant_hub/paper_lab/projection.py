from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
import sqlite3

from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from .database import paper_lab_connection
from .identity import stable_public_id
from .importer import _canonical_json


@dataclass(frozen=True, slots=True)
class ProjectionReport:
    status: str
    source_revision_sha256: str
    tag_component_count: int
    concept_block_count: int
    evidence_count: int
    covered_paper_count: int
    total_paper_count: int
    created_component_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ComponentProjector:
    """从已验证 Paper Lab 投影重建组件；绝不覆盖人工策展字段。"""

    def __init__(self, settings: Settings):
        self.settings = settings

    def rebuild(self) -> ProjectionReport:
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            associations = connection.execute(
                """
                SELECT pt.paper_id,tv.layer,tv.tag_text,tv.review_status,lp.canonical_title
                FROM paper_tag pt
                JOIN tag_vocabulary tv ON tv.tag_id=pt.tag_id
                JOIN lab_paper lp ON lp.paper_id=pt.paper_id
                ORDER BY pt.paper_id,tv.layer,tv.tag_text
                """
            ).fetchall()
            canonical = "\n".join(
                f"{row['paper_id']}\t{row['layer']}\t{row['tag_text']}\t{row['review_status']}"
                for row in associations
            )
            revision = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            by_tag: defaultdict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
            by_paper: defaultdict[str, set[str]] = defaultdict(set)
            for row in associations:
                key = (row["layer"], row["tag_text"])
                by_tag[key].append(row)
                by_paper[row["paper_id"]].add(f"{row['layer']}::{row['tag_text']}")

            co_occurrence: defaultdict[str, defaultdict[str, int]] = defaultdict(
                lambda: defaultdict(int)
            )
            for component_ids in by_paper.values():
                ordered = sorted(component_ids)
                for index, left in enumerate(ordered):
                    for right in ordered[index + 1:]:
                        co_occurrence[left][right] += 1
                        co_occurrence[right][left] += 1

            created = 0
            evidence_count = 0
            projected: dict[str, str] = {}
            with immediate_transaction(connection):
                for (layer, tag_text), refs in sorted(by_tag.items()):
                    legacy_component_id = f"{layer}::{tag_text}"
                    existing = connection.execute(
                        """
                        SELECT component_id FROM concept_component
                        WHERE component_kind='tag_component'
                          AND legacy_component_id=? AND source_revision_sha256=?
                        """,
                        (legacy_component_id, revision),
                    ).fetchone()
                    if existing is not None:
                        component_id = existing["component_id"]
                    else:
                        version = int(connection.execute(
                            """
                            SELECT coalesce(max(version),0)+1 FROM concept_component
                            WHERE component_kind='tag_component' AND legacy_component_id=?
                            """,
                            (legacy_component_id,),
                        ).fetchone()[0])
                        component_id = stable_public_id(
                            "labcomponent", "tag_projection", legacy_component_id, revision,
                        )
                        prior = connection.execute(
                            """
                            SELECT curated_payload_json FROM concept_component
                            WHERE component_kind='tag_component' AND legacy_component_id=?
                            ORDER BY version DESC LIMIT 1
                            """,
                            (legacy_component_id,),
                        ).fetchone()
                        curated = prior["curated_payload_json"] if prior else "{}"
                        payload = {
                            "component_id": legacy_component_id,
                            "layer": layer,
                            "tag": tag_text,
                            "display_name": tag_text.split("-", 1)[-1],
                            "paper_count": len(refs),
                            "references": [
                                {
                                    "paper_id": row["paper_id"],
                                    "legacy_id": connection.execute(
                                        "SELECT legacy_id FROM lab_paper WHERE paper_id=?",
                                        (row["paper_id"],),
                                    ).fetchone()[0],
                                    "title": row["canonical_title"],
                                    "fact_kind": "deterministic_paper_tag_projection",
                                }
                                for row in refs
                            ],
                            "co_occurrences": dict(
                                sorted(
                                    co_occurrence[legacy_component_id].items(),
                                    key=lambda item: (-item[1], item[0]),
                                )
                            ),
                        }
                        connection.execute(
                            """
                            INSERT INTO concept_component(
                                component_id,component_kind,legacy_component_id,layer,
                                display_name,version,automatic_payload_json,
                                curated_payload_json,source_revision_sha256,status,created_at
                            ) VALUES(?,'tag_component',?,?,?,?,?,?,?,'validated',?)
                            """,
                            (
                                component_id, legacy_component_id, layer,
                                payload["display_name"], version, _canonical_json(payload),
                                curated, revision, now,
                            ),
                        )
                        created += 1
                    projected[legacy_component_id] = component_id
                    for row in refs:
                        result = connection.execute(
                            """
                            SELECT rr.result_id
                            FROM reading_result rr
                            JOIN reading_run run ON run.run_id=rr.run_id
                            JOIN lab_paper_version pv ON pv.paper_version_id=run.paper_version_id
                            WHERE pv.paper_id=?
                            ORDER BY rr.created_at DESC LIMIT 1
                            """,
                            (row["paper_id"],),
                        ).fetchone()
                        evidence_id = stable_public_id(
                            "labevidence", component_id, row["paper_id"], revision,
                        )
                        inserted = connection.execute(
                            """
                            INSERT OR IGNORE INTO component_evidence(
                                component_evidence_id,component_id,paper_id,result_id,
                                evidence_kind,evidence_locator_json,provenance_urn,created_at
                            ) VALUES(?,?,?,?, 'reading_result',?,?,?)
                            """,
                            (
                                evidence_id, component_id, row["paper_id"],
                                result["result_id"] if result else None,
                                _canonical_json({
                                    "layer": layer,
                                    "tag": tag_text,
                                    "fact_kind": "deterministic_extraction",
                                }),
                                f"qrh:paper-lab-projection:{revision}",
                                now,
                            ),
                        ).rowcount
                        evidence_count += inserted

                block_rows = connection.execute(
                    """
                    SELECT c.* FROM concept_component c
                    JOIN (
                        SELECT legacy_component_id,max(version) AS version
                        FROM concept_component WHERE component_kind='concept_block'
                        GROUP BY legacy_component_id
                    ) latest
                    ON latest.legacy_component_id=c.legacy_component_id
                   AND latest.version=c.version
                    WHERE c.component_kind='concept_block'
                    ORDER BY c.legacy_component_id
                    """
                ).fetchall()
                for block in block_rows:
                    if block["source_revision_sha256"] == revision:
                        continue
                    old_payload = json.loads(block["automatic_payload_json"])
                    related = old_payload.get("related_tags") or []
                    paper_ids: set[str] = set()
                    for legacy_component_id in related:
                        for row in by_tag.get(tuple(legacy_component_id.split("::", 1)), []):
                            paper_ids.add(row["paper_id"])
                    representatives = []
                    for paper_id in sorted(
                        paper_ids,
                        key=lambda value: int(connection.execute(
                            "SELECT coalesce(legacy_id,'2147483647') FROM lab_paper WHERE paper_id=?",
                            (value,),
                        ).fetchone()[0]),
                    )[:5]:
                        paper = connection.execute(
                            "SELECT legacy_id,canonical_title FROM lab_paper WHERE paper_id=?",
                            (paper_id,),
                        ).fetchone()
                        representatives.append({
                            "paper_id": paper_id,
                            "legacy_id": paper["legacy_id"],
                            "title": paper["canonical_title"],
                            "fact_kind": "deterministic_related_tag_projection",
                        })
                    new_payload = dict(old_payload)
                    new_payload["representative_papers"] = representatives
                    new_payload["paper_count"] = len(paper_ids)
                    new_payload["projection_revision"] = revision
                    version = int(block["version"]) + 1
                    component_id = stable_public_id(
                        "labcomponent", "block_projection", block["legacy_component_id"], revision,
                    )
                    if connection.execute(
                        "SELECT 1 FROM concept_component WHERE component_id=?", (component_id,)
                    ).fetchone() is None:
                        connection.execute(
                            """
                            INSERT INTO concept_component(
                                component_id,component_kind,legacy_component_id,layer,
                                display_name,version,automatic_payload_json,
                                curated_payload_json,source_revision_sha256,status,created_at
                            ) VALUES(?,'concept_block',?,?,?,?,?,?,?, ?,?)
                            """,
                            (
                                component_id, block["legacy_component_id"], block["layer"],
                                block["display_name"], version, _canonical_json(new_payload),
                                block["curated_payload_json"], revision, block["status"], now,
                            ),
                        )
                        created += 1

                total = int(connection.execute("SELECT count(*) FROM lab_paper").fetchone()[0])
                covered = len(by_paper)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO paper_lab_event(
                        event_id,aggregate_type,aggregate_id,event_type,payload_json,created_at
                    ) VALUES(?,'component_projection',?,'component_projection_built',?,?)
                    """,
                    (
                        stable_public_id("labevent", "component_projection", revision),
                        revision,
                        _canonical_json({
                            "tag_components": len(projected),
                            "concept_blocks": len(block_rows),
                            "covered_papers": covered,
                            "total_papers": total,
                        }),
                        now,
                    ),
                )
            return ProjectionReport(
                status="PASS" if covered == total else "PARTIAL",
                source_revision_sha256=revision,
                tag_component_count=len(projected),
                concept_block_count=len(block_rows),
                evidence_count=evidence_count,
                covered_paper_count=covered,
                total_paper_count=total,
                created_component_count=created,
            )
