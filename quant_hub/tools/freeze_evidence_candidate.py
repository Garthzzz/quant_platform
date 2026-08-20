from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from quant_hub.config import stat_is_reparse_point
from quant_hub.platform.migrations import schema_hash


MANIFEST_NAME = "C_CANDIDATE_MANIFEST.json"
LEDGER_INVENTORY_FORMAT = "qrh-research-paper-inventory/v1"
CANDIDATE_INVENTORY_FORMAT = "qrh-research-paper-candidate-inventory/v1"
EXPECTED_ARCHIVE_FILES = 230
EXPECTED_ARCHIVE_BYTES = 18_317_236


def _files(root: Path, *, exclude_names: set[str] | None = None) -> list[Path]:
    excluded = exclude_names or set()
    result: list[Path] = []
    for candidate in root.rglob("*"):
        if candidate.name in excluded or "__pycache__" in candidate.parts:
            continue
        info = candidate.lstat()
        if stat_is_reparse_point(info):
            raise RuntimeError(f"candidate tree contains a reparse point: {candidate}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError(f"candidate artifact is not a regular single-link file: {candidate}")
        if candidate.name.endswith(("-wal", "-shm")):
            if info.st_size:
                raise RuntimeError(
                    f"candidate tree contains a non-empty SQLite sidecar: {candidate}"
                )
            continue
        if candidate.suffix == ".pyc":
            continue
        result.append(candidate)
    return result


def _record(project: Path, path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": path.relative_to(project).as_posix(),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _tree_facts(project: Path, root: Path) -> dict[str, object]:
    records = [_record(project, path) for path in _files(root)]
    records.sort(key=lambda row: str(row["path"]))
    payload = json.dumps(
        records, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "root": root.relative_to(project).as_posix(),
        "file_count": len(records),
        "bytes": sum(int(row["bytes"]) for row in records),
        "tree_sha256": hashlib.sha256(payload).hexdigest(),
        "records": records,
    }


def _database_facts(root: Path) -> dict[str, object]:
    evidence_path = root / "db" / "research_papers.sqlite3"
    platform_path = root / "db" / "platform.sqlite3"
    with sqlite3.connect(
        f"file:{evidence_path.as_posix()}?mode=ro&immutable=1", uri=True
    ) as connection:
        counts = {
            table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
            for table in (
                "paper_clue",
                "paper_candidate",
                "paper",
                "citation_occurrence",
                "citation_ledger_entry",
                "citation_binding",
                "paper_resource",
                "evidence_excerpt",
                "paper_category",
                "paper_category_assignment",
                "paper_category_assertion",
                "paper_category_assignment_detail",
                "paper_core_conclusion",
                "paper_core_conclusion_evidence",
                "paper_institution_resolution",
                "organization",
                "person_affiliation_assertion",
                "paper_analysis",
                "paper_reading_task",
                "paper_reading_run",
                "paper_reading_conclusion_binding",
                "research_paper_relation",
            )
        }
        counts["unlinked_ledger_entry"] = int(
            connection.execute(
                "SELECT count(*) FROM citation_ledger_entry WHERE clue_id IS NULL"
            ).fetchone()[0]
        )
        counts["successful_reading_run"] = int(
            connection.execute(
                "SELECT count(*) FROM paper_reading_run WHERE result_status='succeeded'"
            ).fetchone()[0]
        )
        counts["failed_reading_run"] = int(
            connection.execute(
                "SELECT count(*) FROM paper_reading_run WHERE result_status='failed'"
            ).fetchone()[0]
        )
        counts["unresolved_institution_resolution"] = int(
            connection.execute(
                """
                SELECT count(*) FROM paper_institution_resolution
                WHERE resolution_status='unresolved'
                """
            ).fetchone()[0]
        )
        inventory = connection.execute(
            """
            SELECT content_sha256,bytes,relative_path FROM paper_inventory_export
            WHERE format_version=?
            """,
            (LEDGER_INVENTORY_FORMAT,),
        ).fetchone()
        candidate_inventory = connection.execute(
            """
            SELECT content_sha256,bytes,relative_path FROM paper_inventory_export
            WHERE format_version=?
            """,
            (CANDIDATE_INVENTORY_FORMAT,),
        ).fetchone()
        active = connection.execute(
            "SELECT evidence_release_id,release_snapshot_urn,revision FROM active_evidence_release"
        ).fetchone()
        release = (
            connection.execute(
                """
                SELECT artifact_manifest_hash,source_snapshot_hash,requirements_manifest_hash
                FROM evidence_release WHERE evidence_release_id=?
                """,
                (active[0],),
            ).fetchone()
            if active is not None
            else None
        )
        evidence_schema = schema_hash(connection)
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    if not platform_path.is_file():
        raise RuntimeError("candidate lacks its platform authority database")
    with sqlite3.connect(
        f"file:{platform_path.as_posix()}?mode=ro&immutable=1", uri=True
    ) as connection:
        platform_integrity = str(
            connection.execute("PRAGMA integrity_check").fetchone()[0]
        )
    if inventory is None or candidate_inventory is None:
        raise RuntimeError("candidate database lacks one of the deterministic inventories")
    return {
        "counts": counts,
        "inventory_sha256": str(inventory[0]),
        "inventory_bytes": int(inventory[1]),
        "inventory_relative_path": str(inventory[2]),
        "candidate_inventory_sha256": str(candidate_inventory[0]),
        "candidate_inventory_bytes": int(candidate_inventory[1]),
        "candidate_inventory_relative_path": str(candidate_inventory[2]),
        "schema_sha256": evidence_schema,
        "integrity_check": integrity,
        "foreign_key_violation_count": foreign_keys,
        "platform_integrity_check": platform_integrity,
        "active_release": (
            {
                "evidence_release_id": str(active[0]),
                "release_snapshot_urn": str(active[1]),
                "revision": int(active[2]),
                "artifact_manifest_hash": str(release[0]),
                "source_snapshot_hash": str(release[1]),
                "requirements_manifest_hash": str(release[2]),
            }
            if active is not None and release is not None
            else None
        ),
    }


def _manifest(
    project: Path,
    *,
    replay_slug: str,
    delivery_slug: str,
    expected_inventory: str,
    expected_candidate_inventory: str,
    expected_schema: str,
) -> dict[str, object]:
    formal = project / "quant_hub"
    replay_root = formal / "var" / "replay" / "evidence" / replay_slug
    delivery_root = formal / "var" / "delivery" / "evidence" / delivery_slug
    if not replay_root.is_dir() or not delivery_root.is_dir():
        raise RuntimeError("reviewed replay and delivery roots must both exist")

    source_files = _files(
        formal / "src" / "quant_hub",
        exclude_names={"C_GATE_REPORT.md", "C_GATE_REVIEW.md"},
    )
    source_files += _files(formal / "migrations")
    source_files += _files(formal / "fixtures")
    source_files += _files(formal / "tests")
    source_files += _files(formal / "tools")
    source_files += [formal / "pyproject.toml", formal / "README.md"]
    source_files = sorted(set(source_files), key=lambda path: path.as_posix())
    input_files = _files(project / "project_state" / "workers" / "e_evidence_bulk_data")
    input_files += _files(
        project / "project_state" / "workers" / "archive_paper_clues"
    )
    input_files = sorted(set(input_files), key=lambda path: path.as_posix())
    replay_files = _files(replay_root, exclude_names={MANIFEST_NAME})
    delivery_files = _files(delivery_root, exclude_names={MANIFEST_NAME})
    archive_facts = _tree_facts(project, project / "reference" / "archive")
    if (
        archive_facts["file_count"] != EXPECTED_ARCHIVE_FILES
        or archive_facts["bytes"] != EXPECTED_ARCHIVE_BYTES
    ):
        raise RuntimeError("live reference/archive count or byte conservation changed")
    replay_facts = _database_facts(replay_root)
    delivery_facts = _database_facts(delivery_root)
    expected_counts = {
        "paper_clue": 245,
        "paper_candidate": 245,
        "paper": 18,
        "citation_occurrence": 4630,
        "citation_ledger_entry": 5181,
        "citation_binding": 5181,
        "paper_resource": 18,
        "evidence_excerpt": 18,
        "paper_category": 4,
        "paper_category_assignment": 23,
        "paper_category_assertion": 18,
        "paper_category_assignment_detail": 23,
        "paper_core_conclusion": 18,
        "paper_core_conclusion_evidence": 18,
        "paper_institution_resolution": 18,
        "unresolved_institution_resolution": 18,
        "organization": 0,
        "person_affiliation_assertion": 0,
        "paper_analysis": 36,
        "paper_reading_task": 18,
        "paper_reading_run": 19,
        "successful_reading_run": 18,
        "failed_reading_run": 1,
        "paper_reading_conclusion_binding": 18,
        "unlinked_ledger_entry": 35,
        "research_paper_relation": 367,
    }
    for label, facts in (("replay", replay_facts), ("delivery", delivery_facts)):
        if facts["inventory_sha256"] != expected_inventory:
            raise RuntimeError(f"{label} inventory differs from reviewed hash")
        if facts["candidate_inventory_sha256"] != expected_candidate_inventory:
            raise RuntimeError(f"{label} candidate inventory differs from reviewed hash")
        if facts["schema_sha256"] != expected_schema:
            raise RuntimeError(f"{label} schema differs from reviewed hash")
        if facts["integrity_check"] != "ok" or facts["foreign_key_violation_count"] != 0:
            raise RuntimeError(f"{label} database integrity check failed")
        if facts["counts"] != expected_counts:
            raise RuntimeError(f"{label} database counts differ from reviewed contract")
    if replay_facts["counts"] != delivery_facts["counts"]:
        raise RuntimeError("delivery counts differ from isolated replay")
    if (
        replay_facts["platform_integrity_check"] != "ok"
        or replay_facts["active_release"] is None
        or delivery_facts["platform_integrity_check"] != "ok"
        or delivery_facts["active_release"] is None
    ):
        raise RuntimeError("replay/delivery release-authority boundary is inconsistent")

    return {
        "schema_version": "qrh-evidence-c-candidate-manifest/v2",
        "candidate_id": f"qrh:evidence-c-candidate:{delivery_slug}",
        "selection_policy": {
            "source": (
                "完整 formal src/quant_hub、全部 migrations/fixtures/tests/tools，"
                "以及 pyproject.toml/README.md"
            ),
            "input": "frozen E package plus original candidate/occurrence ledgers",
            "runtime": (
                "isolated replay 与 delivery 都必须冻结 Evidence DB、platform authority DB、"
                "逐字段 PASS certificate receipt 与 active release"
            ),
            "live_archive": (
                "每次生成与 --verify 都从 reference/archive 重新读取全部规则文件并重算树 hash"
            ),
            "exclusions": [
                "__pycache__",
                "*.pyc",
                "*.wal",
                "*.shm",
                MANIFEST_NAME,
                "C_GATE_REPORT.md",
                "C_GATE_REVIEW.md",
            ],
        },
        "reviewed_contract": {
            "candidate_count": 245,
            "ledger_entry_count": 5181,
            "citation_occurrence_count": 4630,
            "paper_count": 18,
            "resource_count": 18,
            "unlinked_ledger_entry_count": 35,
            "inventory_sha256": expected_inventory,
            "candidate_inventory_sha256": expected_candidate_inventory,
            "schema_sha256": expected_schema,
            "category_count": 4,
            "category_assignment_count": 23,
            "core_conclusion_count": 18,
            "explicit_institution_resolution_count": 18,
            "successful_reading_run_count": 18,
            "controlled_failed_reading_probe_count": 1,
            "reading_conclusion_binding_count": 18,
        },
        "live_archive": archive_facts,
        "replay": {"slug": replay_slug, "facts": replay_facts},
        "delivery": {"slug": delivery_slug, "facts": delivery_facts},
        "files": {
            "source": [_record(project, path) for path in source_files],
            "input": [_record(project, path) for path in input_files],
            "replay": [_record(project, path) for path in replay_files],
            "delivery": [_record(project, path) for path in delivery_files],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="冻结或复核 Archive Evidence C 候选。")
    parser.add_argument("--replay-slug", required=True)
    parser.add_argument("--delivery-slug", required=True)
    parser.add_argument("--expected-inventory-sha256", required=True)
    parser.add_argument("--expected-candidate-inventory-sha256", required=True)
    parser.add_argument("--expected-schema-sha256", required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    if arguments.verify and arguments.dry_run:
        raise ValueError("--verify and --dry-run are mutually exclusive")
    project = Path.cwd().resolve(strict=True)
    payload = _manifest(
        project,
        replay_slug=arguments.replay_slug,
        delivery_slug=arguments.delivery_slug,
        expected_inventory=arguments.expected_inventory_sha256,
        expected_candidate_inventory=arguments.expected_candidate_inventory_sha256,
        expected_schema=arguments.expected_schema_sha256,
    )
    body = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    target = (
        project
        / "quant_hub"
        / "var"
        / "delivery"
        / "evidence"
        / arguments.delivery_slug
        / MANIFEST_NAME
    )
    if arguments.dry_run:
        print(
            json.dumps(
                {
                    "manifest_sha256": hashlib.sha256(body).hexdigest(),
                    "archive_tree_sha256": payload["live_archive"]["tree_sha256"],
                    "source_file_count": len(payload["files"]["source"]),
                    "input_file_count": len(payload["files"]["input"]),
                    "replay_file_count": len(payload["files"]["replay"]),
                    "delivery_file_count": len(payload["files"]["delivery"]),
                    "would_write": str(target),
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if arguments.verify:
        if target.read_bytes() != body:
            raise RuntimeError("C candidate manifest or covered artifacts changed")
        print(hashlib.sha256(body).hexdigest())
        return 0
    if target.exists() and target.read_bytes() != body:
        raise RuntimeError("refusing to overwrite a different frozen C candidate")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".c-candidate-", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    print(hashlib.sha256(body).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
