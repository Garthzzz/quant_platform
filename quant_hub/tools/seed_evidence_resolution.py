from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys


FORMAL_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.config import Settings
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.expansion import EvidenceExpansionService
from quant_hub.evidence.providers import (
    ArxivAdapter,
    ResolutionQuery,
    StrongIdentifierQuery,
)
from quant_hub.evidence.repository import EvidenceRepository


DEFAULT_MANIFEST = FORMAL_ROOT / "fixtures" / "evidence" / "expansion_seed_arxiv_v1.json"


def _load_manifest(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "qrh-evidence-resolution-seed/v1":
        raise ValueError("unsupported resolution seed manifest")
    rows = payload.get("items")
    if not isinstance(rows, list) or not rows:
        raise ValueError("resolution seed manifest is empty")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("resolution seed row must be an object")
        source_id = str(raw.get("source_candidate_id") or "")
        arxiv_id = str(raw.get("arxiv_id") or "")
        label = str(raw.get("label") or "")
        if not source_id or not arxiv_id or source_id in seen:
            raise ValueError("resolution seed IDs must be non-empty and unique")
        # ResolutionQuery performs strict arXiv normalization below.
        seen.add(source_id)
        normalized.append(
            {"source_candidate_id": source_id, "arxiv_id": arxiv_id, "label": label}
        )
    return normalized


def _planned_rows(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    adapter = ArxivAdapter()
    output: list[dict[str, object]] = []
    for row in rows:
        provenance = (
            "qrh:evidence:resolution-seed:official-arxiv-page-review:"
            f"{row['source_candidate_id']}:{row['arxiv_id']}"
        )
        query = ResolutionQuery(
            identifiers=(
                StrongIdentifierQuery(
                    scheme="arxiv",
                    raw_value=row["arxiv_id"],
                    source_provenance_urn=provenance,
                ),
            )
        )
        request = adapter.plan(query)[0]
        output.append(
            {
                **row,
                "query": query,
                "request": request,
                "provenance_urn": provenance,
            }
        )
    return output


def _apply(settings: Settings, planned: list[dict[str, object]]) -> list[dict[str, object]]:
    # Applying is explicitly scoped by ``--var-root``.  Initializing here makes the
    # entry point work against both a fresh isolated runtime and a pre-0004 candidate
    # database without requiring an undocumented migration command first.
    EvidenceRepository(settings).initialize()
    service = EvidenceExpansionService(settings)
    results: list[dict[str, object]] = []
    for item in planned:
        source_id = str(item["source_candidate_id"])
        with evidence_connection(settings) as connection:
            candidates = connection.execute(
                """
                SELECT DISTINCT candidate.candidate_id
                FROM paper_candidate AS candidate
                JOIN paper_clue_candidate AS link USING(candidate_id)
                JOIN paper_clue AS clue USING(clue_id)
                WHERE clue.source_candidate_id=?
                ORDER BY candidate.candidate_id
                """,
                (source_id,),
            ).fetchall()
        if len(candidates) != 1:
            results.append(
                {
                    "source_candidate_id": source_id,
                    "status": "blocked_candidate_lookup",
                    "candidate_count": len(candidates),
                }
            )
            continue
        opened, requests = service.enqueue_and_plan(
            str(candidates[0]["candidate_id"]),
            item["query"],
            (ArxivAdapter(),),
            provenance_urn=str(item["provenance_urn"]),
            idempotency_key=f"seed:{source_id}:{item['arxiv_id']}",
        )
        results.append(
            {
                "source_candidate_id": source_id,
                "arxiv_id": item["arxiv_id"],
                "status": opened.state.state,
                "resolution_case_id": opened.resolution_case_id,
                "request_ids": [value.provider_request_id for value in requests],
                "created": opened.created,
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or enqueue exact-arXiv resolution cases. This tool never performs "
            "network requests and never creates canonical papers."
        )
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--project-root", type=Path, default=FORMAL_ROOT.parent)
    parser.add_argument("--var-root", type=Path)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write cases/requests to the explicitly selected --var-root Evidence DB.",
    )
    args = parser.parse_args()
    rows = _load_manifest(args.manifest.resolve())
    planned = _planned_rows(rows)
    if not args.apply:
        print(
            json.dumps(
                {
                    "mode": "plan_only",
                    "count": len(planned),
                    "items": [
                        {
                            "source_candidate_id": item["source_candidate_id"],
                            "arxiv_id": item["arxiv_id"],
                            "request_url": item["request"].url,
                            "identity_effect": "awaiting_review_until_explicit_decision",
                        }
                        for item in planned
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.var_root is None:
        parser.error("--apply requires an explicit --var-root")
    settings = Settings.default(
        project_root=args.project_root,
        var_root=args.var_root,
    )
    try:
        results = _apply(settings, planned)
    except sqlite3.Error as error:
        raise RuntimeError("resolution seed transaction failed") from error
    print(
        json.dumps(
            {"mode": "applied", "count": len(results), "items": results},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if all(item["status"] == "resolving" for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
