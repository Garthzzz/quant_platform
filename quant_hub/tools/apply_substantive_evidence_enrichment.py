"""Apply independently reviewed Evidence enrichment to a fresh candidate only."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FORMAL_ROOT = ROOT / "quant_hub"
SOURCE_ROOT = FORMAL_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.platform.migrations import migrate_up


DEFAULT_SOURCE = FORMAL_ROOT / "var" / "delivery-final-reviewed-v5-20260716-v9"
DEFAULT_REVIEWED = (
    ROOT
    / "project_state"
    / "workers"
    / "evidence_substantive_enrichment_20260716"
    / "reviewed_enrichment.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "project_state"
    / "workers"
    / "evidence_substantive_enrichment_20260716"
    / "quiescent_candidate"
)
PLACEHOLDER_PHRASES = (
    "尚无逐字复核的官方摘要",
    "尚无可追溯的论文来源主张",
    "仅检出历史或未映射版本中的引用记录",
    "当前没有可靠页面可供跳转",
    "不以生成内容补位",
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_reviewed(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    value = json.loads(payload.decode("utf-8"))
    if value.get("schema_version") != "qrh-substantive-evidence-enrichment-reviewed/v1":
        raise RuntimeError("reviewed enrichment schema is invalid")
    papers = value.get("papers")
    if not isinstance(papers, list) or len(papers) != 78:
        raise RuntimeError("reviewed enrichment must contain exactly 78 papers")
    paper_ids = [str(item.get("paper_id") or "") for item in papers if isinstance(item, dict)]
    if len(set(paper_ids)) != 78:
        raise RuntimeError("reviewed enrichment paper identities are incomplete or duplicated")
    encoded = payload.decode("utf-8")
    if any(phrase in encoded for phrase in PLACEHOLDER_PHRASES):
        raise RuntimeError("reviewed enrichment contains a forbidden placeholder phrase")
    return value


def _backup_database(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


def _prepare_output(output: Path) -> None:
    allowed_parent = (
        ROOT / "project_state" / "workers" / "evidence_substantive_enrichment_20260716"
    ).resolve()
    resolved = output.resolve()
    if resolved.parent != allowed_parent or resolved.name != "quiescent_candidate":
        raise RuntimeError("candidate output is outside the dedicated worker root")
    if resolved.exists():
        shutil.rmtree(resolved)
    (resolved / "db").mkdir(parents=True)


def _validate_item(item: dict[str, Any], *, existing_abstract: bool, existing_conclusion: bool) -> None:
    institutions = item.get("institutions")
    if not isinstance(institutions, list) or not institutions or any(
        not isinstance(value, str) or not value.strip() for value in institutions
    ):
        raise RuntimeError(f"institutions are not substantive: {item.get('paper_id')}")
    if not isinstance(item.get("institution_source"), dict):
        raise RuntimeError(f"institution provenance is missing: {item.get('paper_id')}")
    required = (
        "abstract_text",
        "abstract_sha256",
        "abstract_source",
        "abstract_translation_zh",
        "synthesis_zh",
        "core_conclusion_text",
        "core_conclusion_source",
    )
    if not existing_abstract or not existing_conclusion:
        if any(not item.get(field) for field in required):
            raise RuntimeError(f"source content is incomplete: {item.get('paper_id')}")
        abstract = str(item["abstract_text"])
        if _sha256_bytes(abstract.encode("utf-8")) != str(item["abstract_sha256"]):
            raise RuntimeError(f"abstract hash differs: {item.get('paper_id')}")
    relative = item.get("local_pdf_relative_path")
    if relative:
        path = ROOT.joinpath(*Path(str(relative).replace("/", "\\")).parts)
        payload = path.read_bytes()
        if (
            not payload.startswith(b"%PDF-")
            or len(payload) != int(item["local_pdf_bytes"])
            or _sha256_bytes(payload) != str(item["local_pdf_sha256"])
        ):
            raise RuntimeError(f"local PDF identity differs: {item.get('paper_id')}")


def run(source: Path, reviewed_path: Path, output: Path) -> dict[str, Any]:
    reviewed = _load_reviewed(reviewed_path)
    _prepare_output(output)
    shutil.copytree(source / "research_papers", output / "research_papers")
    database = output / "db" / "research_papers.sqlite3"
    _backup_database(source / "db" / "research_papers.sqlite3", database)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        migrate_up(connection, FORMAL_ROOT / "migrations" / "research_papers")
        known = {
            str(row["paper_id"]): {
                "abstract": bool(row["has_abstract"]),
                "conclusion": bool(row["has_conclusion"]),
            }
            for row in connection.execute(
                """
                SELECT paper.paper_id,
                       EXISTS(SELECT 1 FROM evidence_excerpt e WHERE e.paper_id=paper.paper_id) has_abstract,
                       EXISTS(SELECT 1 FROM paper_core_conclusion c WHERE c.paper_id=paper.paper_id) has_conclusion
                FROM paper
                """
            )
        }
        if set(known) != {str(item["paper_id"]) for item in reviewed["papers"]}:
            raise RuntimeError("reviewed enrichment identity set differs from candidate database")
        reviewed_at = str(reviewed["reviewed_at"])
        for item in reviewed["papers"]:
            paper_id = str(item["paper_id"])
            state = known[paper_id]
            _validate_item(
                item,
                existing_abstract=state["abstract"],
                existing_conclusion=state["conclusion"],
            )
            institutions_json = _canonical_json(item["institutions"])
            provenance = "qrh:evidence:substantive-enrichment:" + _sha256_bytes(
                _canonical_json(
                    {
                        "paper_id": paper_id,
                        "institutions": item["institutions"],
                        "abstract_sha256": item.get("abstract_sha256"),
                        "local_pdf_sha256": item.get("local_pdf_sha256"),
                    }
                ).encode("utf-8")
            )
            connection.execute(
                """
                UPDATE paper_catalog_projection
                SET institutions_json=?,projection_revision=projection_revision+1,updated_at=?
                WHERE paper_id=?
                """,
                (institutions_json, reviewed_at, paper_id),
            )
            # ``paper_institution_resolution`` is an immutable historical gate
            # receipt.  A later source review must therefore be represented by
            # the versioned enrichment row below and the current catalog
            # projection, rather than rewriting the earlier unresolved fact.
            connection.execute(
                """
                INSERT INTO evidence_substantive_enrichment(
                    paper_id,institutions_json,institution_source_json,
                    abstract_text,abstract_sha256,abstract_source_json,
                    abstract_translation_zh,synthesis_zh,core_conclusion_text,
                    core_conclusion_source_json,local_pdf_relative_path,
                    local_pdf_sha256,local_pdf_bytes,local_pdf_source_url,
                    provenance_urn,reviewed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    paper_id,
                    institutions_json,
                    _canonical_json(item["institution_source"]),
                    item.get("abstract_text") if not state["abstract"] else None,
                    item.get("abstract_sha256") if not state["abstract"] else None,
                    _canonical_json(item["abstract_source"]) if not state["abstract"] else None,
                    item.get("abstract_translation_zh") if not state["abstract"] else None,
                    item.get("synthesis_zh") if not state["abstract"] else None,
                    item.get("core_conclusion_text") if not state["conclusion"] else None,
                    _canonical_json(item["core_conclusion_source"]) if not state["conclusion"] else None,
                    item.get("local_pdf_relative_path"),
                    item.get("local_pdf_sha256"),
                    item.get("local_pdf_bytes"),
                    item.get("local_pdf_source_url"),
                    provenance,
                    reviewed_at,
                ),
            )
        connection.commit()
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        counts = dict(
            connection.execute(
                """
                SELECT count(*) total,
                       sum(json_array_length(institutions_json)>0) institutions,
                       sum(abstract_text IS NOT NULL) supplemental_abstracts,
                       sum(core_conclusion_text IS NOT NULL) supplemental_conclusions,
                       sum(local_pdf_relative_path IS NOT NULL) local_pdfs
                FROM evidence_substantive_enrichment
                """
            ).fetchone()
        )
    finally:
        connection.close()
    sidecars = [str(path) for path in database.parent.glob("research_papers.sqlite3-*")]
    if sidecars:
        raise RuntimeError(f"candidate database has sidecars: {sidecars}")
    report = {
        "schema_version": "qrh-substantive-evidence-candidate/v1",
        "created_at": datetime.now(UTC).isoformat(),
        "source_delivery": str(source),
        "reviewed_enrichment": str(reviewed_path),
        "reviewed_enrichment_sha256": _sha256_bytes(reviewed_path.read_bytes()),
        "candidate": str(output),
        "database_sha256": _sha256_bytes(database.read_bytes()),
        "integrity": integrity,
        "foreign_key_violations": foreign_keys,
        "counts": counts,
        "status": "PASS" if integrity == "ok" and foreign_keys == 0 else "FAIL",
    }
    report_path = output.parent / "candidate_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--reviewed", type=Path, default=DEFAULT_REVIEWED)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = run(args.source.resolve(), args.reviewed.resolve(), args.output.resolve())
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
