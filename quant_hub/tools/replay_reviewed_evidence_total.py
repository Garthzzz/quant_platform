"""在全新隔离运行根回放旧18基线与已审核 Crossref/arXiv 总交付。

本工具故意要求显式 ``--var-root``，并只接受本 worker 目录的直接子目录。
它不会选择或初始化 live Settings；live Evidence DB 仅在回放前后做字节指纹核对。
回放与发布验证完成后，再通过 SQLite backup 生成无 sidecar 的独立静止候选，
并逐表比对数据库逻辑内容以及 ``research_papers/objects`` 资源闭包。
"""

from __future__ import annotations

import atexit
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import sys
import tempfile
from typing import Any


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
SOURCE_ROOT = FORMAL_ROOT / "src"
KNOWN_LIVE_DATABASE = (
    WORKSPACE_ROOT
    / "quant_hub"
    / "var"
    / "delivery-final-reviewed-v5-20260716-v4"
    / "db"
    / "research_papers.sqlite3"
)
KNOWN_LIVE_DATABASE_BYTES = 37_552_128
KNOWN_LIVE_DATABASE_SHA256 = (
    "13d90a97d271415f3f606a8d8fc014b0d7bbf139261c4c8f2b9bdbdd8d14e97d"
)
FROZEN_V4_DISPLAYABLE_PAPER_SET_BYTES = 2_457
FROZEN_V4_DISPLAYABLE_PAPER_SET_SHA256 = (
    "ecff7f7392916da9cbe5afe50de59c7388ab79afc9f25513899fa45c425e059d"
)
DEDUP_EXPECTATION = (
    WORKSPACE_ROOT
    / "project_state"
    / "workers"
    / "evidence_replay_review"
    / "dedup_expectation_v1.json"
)
DEDUP_EXPECTATION_BYTES = 30_654
DEDUP_EXPECTATION_SHA256 = (
    "5a7958c389a43892bee1c0d7e0952c9db6a9581eadca8f037f43c782504812a0"
)
CROSSREF_RIGHTS_BYTES = 69_079
CROSSREF_RIGHTS_SHA256 = (
    "6e6e462d577b78901fd0335eced9aa10db954e5bcd50224b03ef085501a93b3e"
)
U055_FULLTEXT_BYTES = 11_901
U055_FULLTEXT_SHA256 = (
    "d17c1e018d3e4d2daebe458ab47e5c9bbae482e50e4a4cf35b85048c307d36df"
)
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from quant_hub.app import create_app
from quant_hub.config import Settings
from quant_hub.evidence.bulk import import_bulk_evidence
from quant_hub.evidence.database import evidence_connection
from quant_hub.evidence.ids import normalize_identifier, stable_evidence_id
from quant_hub.evidence.releases import EvidenceReleaseService
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.resources import EvidenceResourceStore
from quant_hub.evidence.reviewed_material_importer import (
    ReviewedMaterialImporter,
    ReviewedMaterialSources,
)
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.ids import stable_sha256
from quant_hub.platform.releases import ReleaseAuthority
from quant_hub.runtime_seal import (
    assert_material,
    database_contract,
    file_identity,
    require_no_sqlite_sidecars,
    safe_tree,
)


def _fingerprint(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"path": str(path), "exists": False}
    return {
        "path": str(path),
        "exists": True,
        **file_identity(path),
    }


def _database_fingerprint(path: Path) -> dict[str, dict[str, object]]:
    return {
        "database": _fingerprint(path),
        "wal": _fingerprint(Path(f"{path}-wal")),
        "shm": _fingerprint(Path(f"{path}-shm")),
        "journal": _fingerprint(Path(f"{path}-journal")),
    }


def _assert_arxiv_rights_probe_details(
    blocked_details: dict[str, dict[str, Any]],
    approved_details: dict[str, dict[str, Any]],
) -> None:
    """验证 API 层没有重新把官方摘要与本地 PDF 权限耦合。"""

    if any(
        len(detail["abstract_excerpts"]) != 1
        or detail["local_resources"]
        or detail["reading_tasks"]
        or len(detail["core_conclusions"]) != 1
        or detail["core_conclusions"][0].get("evidence_scope")
        != "official_abstract"
        for detail in blocked_details.values()
    ) or any(
        len(detail["abstract_excerpts"]) != 1
        or len(detail["local_resources"]) != 1
        or len(detail["reading_tasks"]) != 1
        or not detail["core_conclusions"]
        for detail in approved_details.values()
    ):
        raise RuntimeError("arXiv blocked/CC BY resource API boundaries are incorrect")


def _resolve_known_live_database(requested: Path) -> Path:
    if not KNOWN_LIVE_DATABASE.is_file():
        raise RuntimeError(
            "frozen known live database is unavailable; restore the retired "
            "V4 replay fixture before running this historical replay"
        )
    expected = KNOWN_LIVE_DATABASE.resolve(strict=True)
    resolved = requested.resolve(strict=True)
    if resolved != expected:
        raise RuntimeError(f"--live-database must be the frozen known live database: {expected}")
    identity = file_identity(resolved)
    if {
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
    } != {
        "bytes": KNOWN_LIVE_DATABASE_BYTES,
        "sha256": KNOWN_LIVE_DATABASE_SHA256,
    }:
        raise RuntimeError("frozen V4 live-monitor database identity changed")
    fingerprint = _database_fingerprint(resolved)
    if any(
        fingerprint[name].get("exists") is True
        for name in ("wal", "shm", "journal")
    ):
        raise RuntimeError("frozen V4 live-monitor database has SQLite sidecars")
    return resolved


def _frozen_v4_displayable_archive_relation_papers(
    research_database: Path | None = None,
) -> int:
    """复制冻结四库后再按目录/详情共用语义重算，绝不 RW 打开 V4。"""

    source_var = KNOWN_LIVE_DATABASE.parents[1]
    source_databases = {
        name: source_var / "db" / f"{name}.sqlite3"
        for name in ("platform", "archive", "research_papers", "paper_lab")
    }
    if research_database is not None:
        selected_research = research_database.resolve(strict=True)
        if not selected_research.is_relative_to(WORKSPACE_ROOT.resolve(strict=True)):
            raise RuntimeError("displayable relation research DB escapes workspace")
        source_databases["research_papers"] = selected_research
    before = {name: _database_fingerprint(path) for name, path in source_databases.items()}
    if any(
        fingerprint[sidecar].get("exists") is True
        for fingerprint in before.values()
        for sidecar in ("wal", "shm", "journal")
    ):
        raise RuntimeError("frozen V4 database set has SQLite sidecars")
    with tempfile.TemporaryDirectory(
        dir=FORMAL_ROOT, prefix=".displayable-relation-audit-"
    ) as temporary:
        isolated_var = Path(temporary) / "var"
        isolated_db = isolated_var / "db"
        isolated_db.mkdir(parents=True)
        for name, source in source_databases.items():
            shutil.copyfile(source, isolated_db / f"{name}.sqlite3")
        settings = Settings.default(
            project_root=WORKSPACE_ROOT,
            var_root=isolated_var,
        )
        service = EvidenceQueryService(settings)
        papers = service.list_papers(limit=500)["papers"]
        paper_ids = {str(paper["paper_id"]) for paper in papers}
        # This helper verifies an immutable V4 receipt.  Preserve that receipt's
        # original meaning (relations mapped into the current Archive only),
        # even though the current UI additionally exposes valid historical
        # occurrences through a citation-context fallback page.
        with evidence_connection(settings) as connection:
            rows_by_paper = service._archive_relation_rows_by_paper(
                connection, paper_ids
            )
            archive_index = service._archive_link_index()
            # Recount the V4 receipt with V4's original exact-current-path
            # semantics.  Current presentation code also indexes reviewed path
            # aliases; applying that newer alias policy retroactively would turn
            # an identifier-only historical clue into a displayable reference.
            exact_current_index = {
                source_path: target
                for source_path, target in archive_index.items()
                if str(source_path) == str(target.get("source_path") or "")
            }
            displayable_paper_ids: list[str] = []
            for paper_id in paper_ids:
                rows = rows_by_paper.get(paper_id, [])
                current_core = [
                    relation
                    for relation in service._present_archive_relations(
                        rows, exact_current_index, core_only=True
                    )
                    if relation.get("source_resolution")
                    == "current_archive_document"
                ]
                current_relations = [
                    relation
                    for relation in service._present_archive_relations(
                        rows, exact_current_index
                    )
                    if relation.get("source_resolution")
                    == "current_archive_document"
                ]
                current_references = (
                    []
                    if current_core
                    else service._select_archive_reference_relations(
                        current_relations
                    )
                )
                if current_core or current_references:
                    displayable_paper_ids.append(paper_id)
            frozen_set_payload = (
                "\n".join(sorted(displayable_paper_ids)) + "\n"
            ).encode("utf-8")
            if (
                len(frozen_set_payload) != FROZEN_V4_DISPLAYABLE_PAPER_SET_BYTES
                or hashlib.sha256(frozen_set_payload).hexdigest()
                != FROZEN_V4_DISPLAYABLE_PAPER_SET_SHA256
            ):
                raise RuntimeError(
                    "frozen V4 displayable paper identity set changed"
                )
    after = {name: _database_fingerprint(path) for name, path in source_databases.items()}
    if before != after:
        raise RuntimeError("frozen V4 database set changed during displayable relation audit")
    return len(displayable_paper_ids)


def _workspace_file_descriptor(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    workspace = WORKSPACE_ROOT.resolve(strict=True)
    if not resolved.is_relative_to(workspace):
        raise RuntimeError(f"reviewed input escapes workspace: {resolved}")
    identity = file_identity(resolved)
    return {
        "path": resolved.relative_to(workspace).as_posix(),
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
    }


def _validate_declared_source(descriptor: object, *, label: str) -> dict[str, object]:
    if not isinstance(descriptor, dict):
        raise RuntimeError(f"{label}: source descriptor must be an object")
    relative = Path(str(descriptor.get("path") or ""))
    if relative.is_absolute() or not relative.parts:
        raise RuntimeError(f"{label}: source path must be workspace-relative")
    actual = _workspace_file_descriptor(WORKSPACE_ROOT / relative)
    expected = {
        "path": relative.as_posix(),
        "bytes": int(descriptor.get("bytes") or -1),
        "sha256": str(descriptor.get("sha256") or ""),
    }
    if actual != expected:
        raise RuntimeError(f"{label}: source bytes differ from independent expectation")
    return actual


def _load_dedup_expectation() -> tuple[dict[str, object], dict[str, object]]:
    identity = _workspace_file_descriptor(DEDUP_EXPECTATION)
    if (
        identity["path"]
        != "project_state/workers/evidence_replay_review/dedup_expectation_v1.json"
        or identity["bytes"] != DEDUP_EXPECTATION_BYTES
        or identity["sha256"] != DEDUP_EXPECTATION_SHA256
    ):
        raise RuntimeError("independent dedup expectation identity changed")
    payload_bytes = DEDUP_EXPECTATION.read_bytes()
    if (
        len(payload_bytes) != DEDUP_EXPECTATION_BYTES
        or hashlib.sha256(payload_bytes).hexdigest() != DEDUP_EXPECTATION_SHA256
    ):
        raise RuntimeError("independent dedup expectation changed while reading")
    value = json.loads(payload_bytes.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("independent dedup expectation must be an object")
    if value.get("schema_version") != "qrh-reviewed-evidence-dedup-expectation/v1":
        raise RuntimeError("unsupported independent dedup expectation schema")

    policy = value.get("policy")
    counts = value.get("expected_counts")
    projections = value.get("projection_hashes")
    baseline = value.get("baseline")
    incoming = value.get("incoming")
    denied = value.get("denied")
    sources = value.get("sources")
    if (
        not isinstance(policy, dict)
        or not isinstance(counts, dict)
        or not isinstance(projections, dict)
        or not isinstance(baseline, list)
        or not isinstance(incoming, list)
        or not isinstance(denied, list)
        or not isinstance(sources, list)
    ):
        raise RuntimeError("independent dedup expectation is malformed")
    expected_counts = {
        "baseline": 18,
        "crossref_incoming": 31,
        "arxiv_incoming": 29,
        "formal_citation_incoming": 53,
        "associated_method_origin_incoming": 7,
        "incoming": 60,
        "incoming_unique_identity_keys": 60,
        "incoming_baseline_overlap": 0,
        "created_new_canonical": 60,
        "reused_baseline": 0,
        "reused_incoming": 0,
        "canonical_total": 78,
    }
    if counts != expected_counts:
        raise RuntimeError("independent dedup expected counts changed")
    if (
        policy.get("normalizer")
        != "quant_hub.evidence.ids.normalize_identifier/v1"
        or policy.get("identity_key_format")
        != "{scheme}:{normalized_identifier}"
        or policy.get("automatic_reuse_rule")
        != "same_scheme_and_same_normalized_identifier_only"
        or policy.get("cross_scheme_auto_merge") is not False
        or policy.get("version_family_auto_merge") is not False
        or policy.get(
            "crossref_and_arxiv_manifestations_remain_separate_without_explicit_provenance_backed_relationship"
        )
        is not True
        or policy.get("expected_paper_id_formula")
        != "stable_evidence_id('paper','canonical-paper/v1',identity_key)"
    ):
        raise RuntimeError("independent dedup policy changed")
    _validate_declared_source(
        policy.get("normalizer_source"), label="dedup normalizer source"
    )

    expected_roles = {
        "old_18_frozen_input_manifest",
        "old_18_frozen_artifact_manifest",
        "old_18_normalized_identifier_manifest",
        "crossref_frozen_decisions",
        "crossref_independent_identity_verdicts",
        "arxiv_total_delivery_subject",
        "arxiv_total_resolution_seed",
        "arxiv_first_batch_archive_relations",
        "arxiv_new_batch_archive_relations",
        "arxiv_identity_and_no_auto_merge_review",
    }
    if {
        str(row.get("role")) for row in sources if isinstance(row, dict)
    } != expected_roles or len(sources) != len(expected_roles):
        raise RuntimeError("independent dedup source set changed")
    for row in sources:
        if not isinstance(row, dict):
            raise RuntimeError("independent dedup source row is malformed")
        _validate_declared_source(row, label=f"dedup source {row.get('role')}")

    if (
        len(denied) != 1
        or not isinstance(denied[0], dict)
        or denied[0].get("source_candidate_id") != "P095"
        or denied[0].get("identity_key") != "doi:10.3386/w16972"
        or denied[0].get("identity_verdict") != "FAIL"
        or denied[0].get("expected_action") != "excluded_no_receipt"
    ):
        raise RuntimeError("independent dedup denial set changed")
    action_projection = projections.get("incoming_action_tsv")
    if (
        projections.get("baseline_identity_keys_lf_sha256")
        != "ddb52f2066e8c0bd1b9532bccf132f1e3d27b78e11a23aabbb1be910c22a2f2d"
        or projections.get("incoming_identity_keys_lf_sha256")
        != "652638ec32249fb035b9a6f24b3ef04c008badc28d6fbddc38294b1cc67de7ef"
        or projections.get("union_identity_keys_lf_sha256")
        != "4a14c5340856b07d99ceb17407bedcb9a37a3a68459292e58ea49f8de53c8ade"
        or not isinstance(action_projection, dict)
        or action_projection.get("rows") != 60
        or action_projection.get("bytes") != 6_325
        or action_projection.get("sha256")
        != "02b9835cf246b3bf9241da49aa8a4efc156f5d7231d4d8d764ea2212a3c3adc7"
    ):
        raise RuntimeError("independent dedup projection seal changed")

    baseline_keys: set[str] = set()
    for row in baseline:
        if not isinstance(row, dict):
            raise RuntimeError("independent baseline dedup row is malformed")
        scheme = str(row.get("scheme") or "")
        normalized = normalize_identifier(
            scheme, str(row.get("normalized_identifier") or "")
        )
        identity_key = f"{scheme}:{normalized}"
        if row.get("identity_key") != identity_key or identity_key in baseline_keys:
            raise RuntimeError("independent baseline identity projection is inconsistent")
        baseline_keys.add(identity_key)
    incoming_keys: set[str] = set()
    expected_row_keys: set[tuple[str, str, str]] = set()
    for row in incoming:
        if not isinstance(row, dict):
            raise RuntimeError("independent incoming dedup row is malformed")
        scheme = str(row.get("scheme") or "")
        normalized = normalize_identifier(
            scheme, str(row.get("normalized_identifier") or "")
        )
        identity_key = f"{scheme}:{normalized}"
        row_key = (
            str(row.get("source_system") or ""),
            str(row.get("source_candidate_id") or ""),
            str(row.get("paper_source_candidate_id") or ""),
        )
        if (
            row.get("identity_key") != identity_key
            or row.get("expected_target_identity_key") != identity_key
            or row.get("expected_action") != "created_new_canonical"
            or row.get("expected_duplicate_of") is not None
            or identity_key in incoming_keys
            or row_key in expected_row_keys
        ):
            raise RuntimeError("independent incoming dedup projection is inconsistent")
        incoming_keys.add(identity_key)
        expected_row_keys.add(row_key)
    if (
        len(baseline) != 18
        or len(incoming) != 60
        or len(baseline_keys) != 18
        or len(incoming_keys) != 60
        or baseline_keys & incoming_keys
    ):
        raise RuntimeError("independent dedup key conservation failed")
    return value, identity


def _build_reviewed_gate_receipt(
    *,
    sources: ReviewedMaterialSources,
    plan: dict[str, object],
    dedup_expectation: dict[str, object],
    dedup_identity: dict[str, object],
) -> dict[str, object]:
    recomputed_plan = ReviewedMaterialImporter.static_plan(sources)
    if recomputed_plan != plan:
        raise RuntimeError("reviewed static plan changed while binding replay inputs")
    recomputed_dedup, recomputed_dedup_identity = _load_dedup_expectation()
    if (
        recomputed_dedup != dedup_expectation
        or recomputed_dedup_identity != dedup_identity
    ):
        raise RuntimeError("independent dedup expectation changed during replay")
    if sources.open_pdf_review_summary is None:
        raise RuntimeError("reviewed gate receipt cannot omit open PDF review")
    open_pdf_root = sources.open_pdf_review_summary.resolve(strict=True).parent
    required_singletons = {
        "crossref_rights_manifest": sources.crossref_rights_manifest,
        "crossref_identity_verdicts": sources.crossref_identity_verdicts,
        "crossref_fulltext_manifest": sources.crossref_fulltext_manifest,
        "arxiv_materials_manifest": sources.arxiv_materials_manifest,
        "arxiv_reading_records": sources.arxiv_reading_records,
        "arxiv_total_delivery_manifest": sources.arxiv_total_delivery_manifest,
        "arxiv_resolution_seed": sources.arxiv_resolution_seed,
        "arxiv_method_origin_inputs": sources.arxiv_method_origin_inputs,
        "arxiv_independent_verdict": sources.arxiv_independent_verdict,
        "open_pdf_review_summary": sources.open_pdf_review_summary,
        "open_pdf_artifact_manifest": open_pdf_root / "artifact_manifest.sha256",
        "open_pdf_independent_verification": (
            open_pdf_root / "independent_verification.json"
        ),
        "open_pdf_final_review": open_pdf_root / "review_final.jsonl",
        "displayable_archive_database": (
            KNOWN_LIVE_DATABASE.parents[1] / "db" / "archive.sqlite3"
        ),
        "displayable_research_database": KNOWN_LIVE_DATABASE,
    }
    if any(path is None for path in required_singletons.values()):
        raise RuntimeError("reviewed gate receipt cannot omit a frozen source")
    input_bindings = {
        label: _workspace_file_descriptor(path)
        for label, path in required_singletons.items()
        if path is not None
    }
    input_bindings["crossref_decisions"] = [
        _workspace_file_descriptor(path) for path in sources.crossref_decisions
    ]
    input_bindings["dedup_expectation"] = dict(dedup_identity)
    if input_bindings["crossref_rights_manifest"] != {
        "path": (
            "project_state/workers/crossref_identity_review/"
            "rights_resource_offers.jsonl"
        ),
        "bytes": CROSSREF_RIGHTS_BYTES,
        "sha256": CROSSREF_RIGHTS_SHA256,
    }:
        raise RuntimeError("frozen Crossref rights manifest identity changed")
    if input_bindings["crossref_fulltext_manifest"] != {
        "path": "project_state/workers/u055_open_pdf_acquisition/manifest.json",
        "bytes": U055_FULLTEXT_BYTES,
        "sha256": U055_FULLTEXT_SHA256,
    }:
        raise RuntimeError("frozen U055 post-GET manifest identity changed")
    if (
        plan.get("crossref_rights_ready_without_pdf_bytes") != []
        or plan.get("crossref_fulltext_failed_closed") != ["U055"]
    ):
        raise RuntimeError("Crossref rights/U055 failed-closed plan set changed")
    verdict = json.loads(
        sources.arxiv_independent_verdict.read_text(encoding="utf-8")
    )
    expected_counts = dedup_expectation.get("expected_counts")
    if not isinstance(expected_counts, dict):
        raise RuntimeError("dedup expectation has no release counts")
    displayable_archive_relation_papers = (
        _frozen_v4_displayable_archive_relation_papers()
    )
    release_expectation = {
        "canonical_papers": int(expected_counts["canonical_total"]),
        "verified_resources": (
            18
            + len(plan["arxiv_storage_approved"])
            + int(plan["open_pdf_allowed_resources"])
        ),
        "canonicalization_receipts": int(expected_counts["incoming"]),
        "formal_receipts": int(expected_counts["formal_citation_incoming"]),
        "method_receipts": int(expected_counts["associated_method_origin_incoming"]),
        "blocked_acquisitions": len(plan["arxiv_license_blocked"])
        + len(plan["crossref_fulltext_failed_closed"]),
        "associated_method_ledger_occurrences": 547,
        "fulltext_conclusion_support": len(plan["arxiv_storage_approved"]),
        "official_abstract_excerpts": 18
        + int(plan["arxiv_official_abstracts_verified"])
        + int(plan["crossref_official_abstracts_verified"]),
        "reviewed_arxiv_official_abstracts": int(
            plan["arxiv_official_abstracts_verified"]
        ),
        "reviewed_crossref_official_abstracts": int(
            plan["crossref_official_abstracts_verified"]
        ),
        "core_conclusions": 18
        + int(plan["arxiv_reviewed"])
        + int(plan["crossref_official_abstracts_verified"]),
        "reviewed_open_pdf_resources": int(plan["open_pdf_allowed_resources"]),
        "displayable_archive_relation_papers": (
            displayable_archive_relation_papers
        ),
    }
    expected_fixed_release = {
        "canonical_papers": 78,
        "canonicalization_receipts": 60,
        "formal_receipts": 53,
        "method_receipts": 7,
        "blocked_acquisitions": 4,
        "associated_method_ledger_occurrences": 547,
        "fulltext_conclusion_support": 26,
        "official_abstract_excerpts": 53,
        "reviewed_arxiv_official_abstracts": 29,
        "reviewed_crossref_official_abstracts": 6,
        "core_conclusions": 53,
        "displayable_archive_relation_papers": 63,
    }
    if (
        any(release_expectation[name] != value for name, value in expected_fixed_release.items())
        or release_expectation["verified_resources"]
        != 18
        + len(plan["arxiv_storage_approved"])
        + release_expectation["reviewed_open_pdf_resources"]
        or release_expectation["reviewed_open_pdf_resources"]
        != int(plan["open_pdf_allowed_resources"])
    ):
        raise RuntimeError("reviewed release expectation changed")
    return {
        "schema_version": "qrh-reviewed-evidence-gate-receipt/v1",
        "fact_boundary": (
            "This receipt binds the exact independently reviewed inputs consumed by the "
            "isolated replay; it does not grant rights beyond the recorded item decisions."
        ),
        "arxiv_independent_gate": {
            "schema_version": verdict.get("schema_version"),
            "overall_status": verdict.get("overall_status"),
            "release_authorized": verdict.get("release_authorized"),
            "subject": verdict.get("subject"),
            "defects": verdict.get("defects"),
        },
        "input_bindings": input_bindings,
        "static_plan_sha256": hashlib.sha256(
            json.dumps(
                plan,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        "dedup_expectation": {
            "schema_version": dedup_expectation.get("schema_version"),
            "expected_counts": dedup_expectation.get("expected_counts"),
            "projection_hashes": dedup_expectation.get("projection_hashes"),
        },
        "crossref_rights_expectation": {
            "rights_ready_without_pdf_bytes": [],
            "fulltext_failed_closed": ["U055"],
            "rights_manifest": input_bindings["crossref_rights_manifest"],
            "u055_post_get_manifest": input_bindings["crossref_fulltext_manifest"],
        },
        "arxiv_official_abstract_expectation": {
            "reviewed_count": int(plan["arxiv_official_abstracts_verified"]),
            "total_with_baseline": release_expectation[
                "official_abstract_excerpts"
            ],
            "normalization_contract": plan[
                "arxiv_official_abstract_normalization_contract"
            ],
            "projection_sha256": plan[
                "arxiv_official_abstract_projection_sha256"
            ],
            "rights_blocked_with_source_evidence": ["P034", "P137", "P143"],
            "local_pdf_rights_are_independent": True,
        },
        "crossref_official_abstract_expectation": {
            "reviewed_count": int(plan["crossref_official_abstracts_verified"]),
            "normalization_contract": plan[
                "crossref_official_abstract_normalization_contract"
            ],
            "projection_sha256": plan[
                "crossref_official_abstract_projection_sha256"
            ],
            "source_claim_not_fulltext_review": True,
        },
        "open_pdf_review_expectation": plan["open_pdf_review"],
        "release_expectation": release_expectation,
    }


def _assert_reviewed_gate_stable(
    expected: dict[str, object],
    *,
    sources: ReviewedMaterialSources,
    plan: dict[str, object],
    dedup_expectation: dict[str, object],
    dedup_identity: dict[str, object],
    label: str,
) -> None:
    actual = _build_reviewed_gate_receipt(
        sources=sources,
        plan=plan,
        dedup_expectation=dedup_expectation,
        dedup_identity=dedup_identity,
    )
    if actual != expected:
        raise RuntimeError(f"reviewed input gate changed during {label}")


def _write_reviewed_gate_receipt(
    *, settings: Settings, receipt: dict[str, object]
) -> dict[str, object]:
    exports = settings.research_papers_root / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    path = exports / "reviewed_total_gate_receipt.json"
    rendered = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    identity = file_identity(path)
    return {
        "relative_path": path.relative_to(settings.research_papers_root).as_posix(),
        "bytes": identity["bytes"],
        "sha256": identity["sha256"],
    }


def _identifier_projection(settings: Settings) -> dict[tuple[str, str], str]:
    with evidence_connection(settings) as connection:
        return {
            (str(row["scheme"]), str(row["normalized_value"])): str(row["paper_id"])
            for row in connection.execute(
                """
                SELECT scheme,normalized_value,paper_id
                FROM identifier_assignment_projection ORDER BY scheme,normalized_value
                """
            )
        }


def _assert_exact_identifier_projection(
    actual: dict[tuple[str, str], str],
    expected: dict[tuple[str, str], str],
    *,
    label: str,
) -> None:
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        mismatched = sorted(
            key for key in set(actual) & set(expected) if actual[key] != expected[key]
        )
        raise RuntimeError(
            f"{label} identifier projection differs from independent expectation; "
            f"missing={missing}, extra={extra}, mismatched={mismatched}"
        )


def _scalar(connection: sqlite3.Connection, sql: str, parameters: tuple[object, ...] = ()) -> int:
    return int(connection.execute(sql, parameters).fetchone()[0])


def _immutable_sqlite_uri(path: Path) -> str:
    return f"file:{path.resolve(strict=True).as_posix()}?mode=ro&immutable=1"


def _logical_database_contract(contract: dict[str, object]) -> dict[str, object]:
    return {
        "integrity": contract["integrity"],
        "foreign_key_violations": contract["foreign_key_violations"],
        "migration_versions": contract["migration_versions"],
        "schema_sha256": contract["schema_sha256"],
        "tables": contract["tables"],
    }


def _quiesce_database(path: Path) -> dict[str, object]:
    with closing(sqlite3.connect(path, isolation_level=None, timeout=30)) as connection:
        checkpoint = tuple(connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())
        if not checkpoint or int(checkpoint[0]) != 0:
            raise RuntimeError(f"SQLite WAL checkpoint remained busy: {checkpoint!r}")
        journal_mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
        if journal_mode.casefold() != "delete":
            raise RuntimeError(f"SQLite did not enter DELETE journal mode: {journal_mode}")
    require_no_sqlite_sidecars((path,))
    return database_contract(path)


def _resource_closure(
    *, database: Path, research_root: Path, expected_resources: int
) -> dict[str, object]:
    objects = research_root / "objects"
    exports = research_root / "exports"
    if not objects.is_dir() or not exports.is_dir():
        raise RuntimeError("quiescent Evidence candidate lacks objects or exports")
    object_tree = safe_tree(objects)
    with closing(sqlite3.connect(_immutable_sqlite_uri(database), uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        rows = list(
            connection.execute(
                """
                SELECT resource_id,relative_path,content_sha256,bytes,media_type,
                       verification_status
                FROM paper_resource ORDER BY resource_id
                """
            )
        )
    if len(rows) != expected_resources:
        raise RuntimeError("quiescent Evidence resource count changed during freeze")
    expected_paths: set[str] = set()
    for row in rows:
        value = str(row["relative_path"])
        if not value or "\\" in value or ":" in value:
            raise RuntimeError(f"non-canonical Evidence resource path: {value!r}")
        relative = PurePosixPath(value)
        if (
            relative.is_absolute()
            or not relative.parts
            or relative.parts[0] != "objects"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise RuntimeError(f"Evidence resource path escapes objects: {value!r}")
        path = research_root.joinpath(*relative.parts)
        identity = file_identity(path)
        if (
            row["media_type"] != "application/pdf"
            or row["verification_status"] != "verified"
            or int(row["bytes"]) != int(identity["bytes"])
            or str(row["content_sha256"]) != identity["sha256"]
            or not path.read_bytes().startswith(b"%PDF-")
        ):
            raise RuntimeError(f"Evidence resource row/file mismatch: {row['resource_id']}")
        expected_paths.add(relative.as_posix())
    actual_paths = {
        path.relative_to(research_root).as_posix()
        for path in objects.rglob("*")
        if path.is_file()
    }
    if actual_paths != expected_paths:
        raise RuntimeError("Evidence database/object tree is not a bidirectional closure")
    return {
        "resource_rows": len(rows),
        "object_files": len(actual_paths),
        "object_tree": object_tree,
        "exports_tree": safe_tree(exports),
    }


def _freeze_quiescent_candidate(
    *,
    settings: Settings,
    replay_root: Path,
    expected_resources: int,
    replay_snapshot_hash: str,
    gate_receipt_identity: dict[str, object],
) -> dict[str, object]:
    source_database = settings.research_papers_database_path
    source_research = settings.research_papers_root
    source_contract = _quiesce_database(source_database)
    source_tree = safe_tree(source_research)
    receipt_relative = PurePosixPath(
        str(gate_receipt_identity.get("relative_path") or "")
    )
    if (
        receipt_relative.is_absolute()
        or receipt_relative.parts[:1] != ("exports",)
        or any(part in {"", ".", ".."} for part in receipt_relative.parts)
    ):
        raise RuntimeError("reviewed gate receipt has an unsafe candidate path")
    source_receipt = source_research.joinpath(*receipt_relative.parts)
    source_receipt_identity = file_identity(source_receipt)
    if (
        source_receipt_identity["bytes"] != gate_receipt_identity.get("bytes")
        or source_receipt_identity["sha256"] != gate_receipt_identity.get("sha256")
    ):
        raise RuntimeError("reviewed gate receipt changed before candidate freeze")

    candidate = replay_root / "quiescent_candidate"
    if candidate.exists():
        raise RuntimeError("quiescent candidate target already exists")
    candidate_database = candidate / "db" / "research_papers.sqlite3"
    candidate_research = candidate / "research_papers"
    candidate_database.parent.mkdir(parents=True, exist_ok=False)
    shutil.copytree(source_research, candidate_research, copy_function=shutil.copy2)
    assert_material(
        safe_tree(source_research), source_tree, label="Evidence replay resource source"
    )
    assert_material(
        safe_tree(candidate_research), source_tree, label="Evidence quiescent resource copy"
    )
    candidate_receipt_identity = file_identity(
        candidate_research.joinpath(*receipt_relative.parts)
    )
    if (
        candidate_receipt_identity["bytes"] != gate_receipt_identity.get("bytes")
        or candidate_receipt_identity["sha256"] != gate_receipt_identity.get("sha256")
    ):
        raise RuntimeError("quiescent candidate lost the reviewed gate receipt")

    with closing(
        sqlite3.connect(_immutable_sqlite_uri(source_database), uri=True, timeout=30)
    ) as source_connection:
        source_connection.execute("PRAGMA query_only=ON")
        with closing(sqlite3.connect(candidate_database, timeout=30)) as target_connection:
            source_connection.backup(target_connection)
            target_connection.commit()
    require_no_sqlite_sidecars((source_database, candidate_database))
    source_contract_after = database_contract(source_database)
    assert_material(
        source_contract_after, source_contract, label="Evidence replay database after backup"
    )
    candidate_contract = database_contract(candidate_database)
    assert_material(
        _logical_database_contract(candidate_contract),
        _logical_database_contract(source_contract),
        label="Evidence quiescent logical database",
    )
    closure = _resource_closure(
        database=candidate_database,
        research_root=candidate_research,
        expected_resources=expected_resources,
    )
    require_no_sqlite_sidecars((source_database, candidate_database))
    return {
        "path": str(candidate),
        "replay_snapshot_hash": replay_snapshot_hash,
        "source_database": {
            "path": str(source_database),
            "identity": file_identity(source_database),
        },
        "candidate_database": {
            "path": str(candidate_database),
            "identity": file_identity(candidate_database),
            "migration_versions": candidate_contract["migration_versions"],
            "schema_sha256": candidate_contract["schema_sha256"],
            "table_count": len(candidate_contract["tables"]),
            "tables": candidate_contract["tables"],
        },
        "logical_database_equal": True,
        "research_papers_tree": safe_tree(candidate_research),
        "reviewed_gate_receipt": dict(gate_receipt_identity),
        "resource_closure": closure,
        "sqlite_sidecars": [],
    }


def _sources() -> ReviewedMaterialSources:
    crossref = WORKSPACE_ROOT / "project_state" / "workers" / "crossref_identity_review"
    arxiv = WORKSPACE_ROOT / "project_state" / "workers" / "arxiv_expansion_materials"
    return ReviewedMaterialSources(
        crossref_decisions=(crossref / "accepted_decisions.jsonl",),
        crossref_rights_manifest=crossref / "rights_resource_offers.jsonl",
        arxiv_materials_manifest=arxiv / "manifest.json",
        arxiv_reading_records=arxiv / "reading_records.json",
        crossref_identity_verdicts=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "independent_identity_verifier"
            / "item_verdicts.jsonl"
        ),
        crossref_fulltext_manifest=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "u055_open_pdf_acquisition"
            / "manifest.json"
        ),
        arxiv_total_delivery_manifest=arxiv / "total_delivery_manifest.json",
        arxiv_resolution_seed=arxiv / "total_resolution_seed.json",
        arxiv_method_origin_inputs=(
            arxiv / "identity_review" / "method_origin_candidate_inputs.json"
        ),
        arxiv_independent_verdict=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "independent_arxiv_verifier_v2"
            / "verdict_v4.json"
        ),
        open_pdf_review_summary=(
            WORKSPACE_ROOT
            / "project_state"
            / "workers"
            / "evidence_open_pdf_review_20260716"
            / "summary.json"
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--var-root", type=Path, required=True)
    parser.add_argument(
        "--live-database",
        type=Path,
        default=KNOWN_LIVE_DATABASE,
    )
    arguments = parser.parse_args()

    allowed_parent = (
        WORKSPACE_ROOT
        / "project_state"
        / "workers"
        / "evidence_canonicalization_bridge"
    ).resolve()
    target = arguments.var_root.resolve()
    if target.parent != allowed_parent:
        raise RuntimeError(f"--var-root must be a direct child of {allowed_parent}")
    if target.exists() and any(target.iterdir()):
        raise RuntimeError("--var-root must be new or empty")

    live_database = _resolve_known_live_database(arguments.live_database)
    live_before = _database_fingerprint(live_database)
    if live_before["database"].get("exists") is not True:
        raise RuntimeError("known live Evidence database is missing")

    def verify_live_database_on_failure() -> None:
        live_after_failure = _database_fingerprint(live_database)
        if live_before != live_after_failure:
            raise RuntimeError(
                "live Evidence database changed during failed isolated replay"
            )

    atexit.register(verify_live_database_on_failure)
    sources = _sources()
    plan = ReviewedMaterialImporter.static_plan(sources)
    dedup_expectation, dedup_expectation_identity = _load_dedup_expectation()
    reviewed_gate_receipt = _build_reviewed_gate_receipt(
        sources=sources,
        plan=plan,
        dedup_expectation=dedup_expectation,
        dedup_identity=dedup_expectation_identity,
    )
    settings = Settings.default(project_root=WORKSPACE_ROOT, var_root=target)
    package = WORKSPACE_ROOT / "project_state" / "workers" / "e_evidence_bulk_data"
    normalized = FORMAL_ROOT / "fixtures" / "evidence" / "normalized_resource_manifest.jsonl"
    baseline = import_bulk_evidence(
        settings,
        package,
        normalized_manifest_path=normalized,
    )
    baseline_repeat = import_bulk_evidence(
        settings,
        package,
        normalized_manifest_path=normalized,
    )
    if baseline_repeat.created or baseline_repeat.source_snapshot_hash != baseline.source_snapshot_hash:
        raise RuntimeError("old-18 baseline replay is not idempotent")

    repository = EvidenceRepository(settings)
    baseline_identifiers = _identifier_projection(settings)
    expected_baseline_rows = dedup_expectation["baseline"]
    assert isinstance(expected_baseline_rows, list)
    expected_baseline_identifiers = {
        (str(row["scheme"]), str(row["normalized_identifier"])): stable_evidence_id(
            "paper", "canonical-paper/v1", str(row["identity_key"])
        )
        for row in expected_baseline_rows
        if isinstance(row, dict)
    }
    with evidence_connection(settings) as connection:
        baseline_papers = _scalar(connection, "SELECT count(*) FROM paper")
        baseline_resources = _scalar(connection, "SELECT count(*) FROM paper_resource")
        baseline_official_abstracts = _scalar(
            connection, "SELECT count(*) FROM evidence_excerpt"
        )
        baseline_core_conclusions = _scalar(
            connection, "SELECT count(*) FROM paper_core_conclusion"
        )
        baseline_official_abstract_conclusions = _scalar(
            connection, "SELECT count(*) FROM paper_core_conclusion_evidence"
        )
    _assert_exact_identifier_projection(
        baseline_identifiers,
        expected_baseline_identifiers,
        label="old-18 baseline",
    )
    if (
        baseline_papers != 18
        or baseline_resources != 18
        or baseline_official_abstracts != 18
        or baseline_core_conclusions != 18
        or baseline_official_abstract_conclusions != 18
    ):
        raise RuntimeError(
            "reviewed baseline differs from the independent old-18 identity expectation"
        )

    importer = ReviewedMaterialImporter(settings)
    first = importer.apply(
        sources,
        review_id="reviewed-evidence-total-20260715",
        reviewed_by="Quant Research Hub independent reviewed-material gate",
        reviewed_at="2026-07-15T00:00:00Z",
        provenance_urn="qrh:evidence:reviewed-total-import:20260715",
    )
    snapshot_after_first = repository.snapshot_hash()
    second = importer.apply(
        sources,
        review_id="reviewed-evidence-total-20260715",
        reviewed_by="Quant Research Hub independent reviewed-material gate",
        reviewed_at="2026-07-15T00:00:00Z",
        provenance_urn="qrh:evidence:reviewed-total-import:20260715",
    )
    snapshot_after_second = repository.snapshot_hash()
    if first.as_dict() != second.as_dict() or snapshot_after_first != snapshot_after_second:
        raise RuntimeError("reviewed total importer is not idempotent")
    _assert_reviewed_gate_stable(
        reviewed_gate_receipt,
        sources=sources,
        plan=plan,
        dedup_expectation=dedup_expectation,
        dedup_identity=dedup_expectation_identity,
        label="post-apply verification",
    )

    final_identifiers = _identifier_projection(settings)
    incoming = [*first.crossref_identities, *first.arxiv_identities]
    expected_incoming_rows = dedup_expectation["incoming"]
    assert isinstance(expected_incoming_rows, list)
    expected_incoming = {
        (
            str(row["source_system"]),
            str(row["source_candidate_id"]),
            str(row["paper_source_candidate_id"]),
        ): row
        for row in expected_incoming_rows
        if isinstance(row, dict)
    }
    expected_incoming_identifiers = {
        (str(row["scheme"]), str(row["normalized_identifier"])): stable_evidence_id(
            "paper", "canonical-paper/v1", str(row["identity_key"])
        )
        for row in expected_incoming_rows
        if isinstance(row, dict)
    }
    expected_final_identifiers = {
        **expected_baseline_identifiers,
        **expected_incoming_identifiers,
    }
    _assert_exact_identifier_projection(
        final_identifiers,
        expected_final_identifiers,
        label="reviewed final",
    )
    consumed_expectations: set[tuple[str, str, str]] = set()
    actual_incoming_keys: set[tuple[str, str]] = set()
    arxiv_storage_approved = set(plan["arxiv_storage_approved"])
    dedup_rows: list[dict[str, object]] = []
    with evidence_connection(settings) as connection:
        for item in incoming:
            key = (item.identifier_scheme, item.normalized_identifier)
            row_key = (
                item.provider,
                item.source_candidate_id,
                item.paper_source_candidate_id,
            )
            expected = expected_incoming.get(row_key)
            if expected is None or row_key in consumed_expectations:
                raise RuntimeError(f"unexpected or duplicate reviewed identity: {row_key!r}")
            expected_key = (
                str(expected["scheme"]),
                str(expected["normalized_identifier"]),
            )
            if key != expected_key:
                raise RuntimeError(f"reviewed identity differs from dedup expectation: {row_key!r}")
            paper_id = final_identifiers[key]
            expected_paper_id = stable_evidence_id(
                "paper", "canonical-paper/v1", str(expected["identity_key"])
            )
            receipt = connection.execute(
                """
                SELECT canonicalization_receipt_id,treatment,paper_id,resource_mode
                FROM evidence_canonicalization_receipt
                WHERE source_candidate_id=? AND paper_source_candidate_id=?
                """,
                (item.source_candidate_id, item.paper_source_candidate_id),
            ).fetchone()
            if receipt is None:
                raise RuntimeError(f"missing receipt for {item.paper_source_candidate_id}")
            expected_resource_mode = (
                "verified_local_resource"
                if item.provider == "arxiv"
                and item.source_candidate_id in arxiv_storage_approved
                else "metadata_only"
            )
            attachments = list(
                connection.execute(
                    """
                    SELECT attachment.paper_id,attachment.resource_id,
                           resource.verification_status,resource.media_type
                    FROM evidence_canonical_resource_attachment AS attachment
                    JOIN paper_resource AS resource USING(resource_id)
                    WHERE attachment.canonicalization_receipt_id=?
                    ORDER BY attachment.resource_id
                    """,
                    (receipt["canonicalization_receipt_id"],),
                )
            )
            if expected_resource_mode == "verified_local_resource":
                attachment_matches = (
                    item.resource_id is not None
                    and len(attachments) == 1
                    and str(attachments[0]["paper_id"]) == expected_paper_id
                    and str(attachments[0]["resource_id"]) == item.resource_id
                    and attachments[0]["verification_status"] == "verified"
                    and attachments[0]["media_type"] == "application/pdf"
                )
            else:
                attachment_matches = item.resource_id is None and attachments == []
            if (
                key in baseline_identifiers
                or key in actual_incoming_keys
                or paper_id != expected_paper_id
                or str(receipt["paper_id"]) != expected_paper_id
                or str(receipt["treatment"]) != expected["treatment"]
                or str(receipt["resource_mode"]) != expected_resource_mode
                or not attachment_matches
                or expected["expected_action"] != "created_new_canonical"
                or expected["expected_target_identity_key"] != expected["identity_key"]
                or expected["expected_duplicate_of"] is not None
            ):
                raise RuntimeError(
                    f"actual dedup action differs from independent expectation: {row_key!r}"
                )
            actual_incoming_keys.add(key)
            consumed_expectations.add(row_key)
            dedup_rows.append(
                {
                    "source_system": item.provider,
                    "source_candidate_id": item.source_candidate_id,
                    "paper_source_candidate_id": item.paper_source_candidate_id,
                    "treatment": str(receipt["treatment"]),
                    "resource_mode": str(receipt["resource_mode"]),
                    "resource_id": item.resource_id,
                    "strong_identifier": str(expected["identity_key"]),
                    "baseline_match": False,
                    "incoming_duplicate_of": None,
                    "action": "created_new_canonical",
                    "expected_target_identity_key": str(
                        expected["expected_target_identity_key"]
                    ),
                    "paper_id": paper_id,
                }
            )
        if consumed_expectations != set(expected_incoming):
            missing = sorted(set(expected_incoming) - consumed_expectations)
            raise RuntimeError(f"reviewed identities missing from replay: {missing}")

        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
        counts = {
            "canonical_papers": _scalar(connection, "SELECT count(*) FROM paper"),
            "strong_identifier_projection": _scalar(
                connection, "SELECT count(*) FROM identifier_assignment_projection"
            ),
            "resources": _scalar(connection, "SELECT count(*) FROM paper_resource"),
            "official_abstract_excerpts": _scalar(
                connection, "SELECT count(*) FROM evidence_excerpt"
            ),
            "official_abstract_excerpts_without_resource": _scalar(
                connection,
                "SELECT count(*) FROM evidence_excerpt WHERE resource_id IS NULL",
            ),
            "reviewed_arxiv_official_abstracts": _scalar(
                connection,
                """
                SELECT count(DISTINCT excerpt.excerpt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN identifier_assignment_projection AS identifier
                  ON identifier.paper_id=receipt.paper_id
                 AND identifier.scheme='arxiv'
                JOIN evidence_excerpt AS excerpt
                  ON excerpt.paper_id=receipt.paper_id
                """,
            ),
            "reviewed_crossref_official_abstracts": _scalar(
                connection,
                """
                SELECT count(DISTINCT excerpt.excerpt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN identifier_assignment_projection AS identifier
                  ON identifier.paper_id=receipt.paper_id
                 AND identifier.scheme='doi'
                JOIN evidence_excerpt AS excerpt
                  ON excerpt.paper_id=receipt.paper_id
                WHERE json_extract(excerpt.locator_json,'$.field')=
                      'crossref.message.abstract'
                """,
            ),
            "core_conclusions": _scalar(
                connection, "SELECT count(*) FROM paper_core_conclusion"
            ),
            "official_abstract_conclusions": _scalar(
                connection,
                "SELECT count(*) FROM paper_core_conclusion_evidence",
            ),
            "metadata_only_receipts_with_official_abstract": _scalar(
                connection,
                """
                SELECT count(DISTINCT receipt.canonicalization_receipt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
                WHERE receipt.resource_mode='metadata_only'
                """,
            ),
            "reviewed_open_pdf_resources": _scalar(
                connection,
                """
                SELECT count(*)
                FROM paper_resource AS resource
                JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
                WHERE fetch.source_request_id LIKE 'reviewed-open-pdf:%'
                  AND fetch.result_status='succeeded'
                  AND fetch.rights_status='verified_open_license'
                  AND resource.verification_status='verified'
                """,
            ),
            "reviewed_open_pdf_catalog_links": _scalar(
                connection,
                """
                SELECT count(*)
                FROM paper_resource AS resource
                JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
                JOIN paper_catalog_projection AS catalog USING(paper_id)
                WHERE fetch.source_request_id LIKE 'reviewed-open-pdf:%'
                  AND EXISTS (
                    SELECT 1 FROM json_each(catalog.local_resources_json)
                    WHERE json_extract(value,'$.resource_id')=resource.resource_id
                  )
                """,
            ),
            "official_abstract_resource_coupling_violations": _scalar(
                connection,
                """
                SELECT count(*)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN identifier_assignment_projection AS identifier
                  ON identifier.paper_id=receipt.paper_id
                 AND identifier.scheme='arxiv'
                WHERE (
                    SELECT count(*) FROM evidence_excerpt AS excerpt
                    WHERE excerpt.paper_id=receipt.paper_id
                      AND excerpt.resource_id IS NULL
                )<>1
                   OR EXISTS (
                       SELECT 1 FROM evidence_excerpt AS excerpt
                       WHERE excerpt.paper_id=receipt.paper_id
                         AND excerpt.resource_id IS NOT NULL
                   )
                """,
            ),
            "blocked_arxiv_official_abstracts": _scalar(
                connection,
                """
                SELECT count(DISTINCT receipt.canonicalization_receipt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
                WHERE receipt.source_candidate_id IN ('P034','P137','P143')
                  AND receipt.resource_mode='metadata_only'
                  AND excerpt.resource_id IS NULL
                """,
            ),
            "blocked_arxiv_source_evidence_violations": _scalar(
                connection,
                """
                SELECT count(*)
                FROM evidence_canonicalization_receipt AS receipt
                WHERE receipt.source_candidate_id IN ('P034','P137','P143')
                  AND (
                    receipt.resource_mode<>'metadata_only'
                    OR (
                        SELECT count(*) FROM evidence_excerpt AS excerpt
                        WHERE excerpt.paper_id=receipt.paper_id
                          AND excerpt.resource_id IS NULL
                    )<>1
                    OR EXISTS (
                        SELECT 1
                        FROM evidence_canonical_resource_attachment AS attachment
                        WHERE attachment.canonicalization_receipt_id=
                              receipt.canonicalization_receipt_id
                    )
                    OR EXISTS (
                        SELECT 1 FROM paper_reading_task AS task
                        WHERE task.paper_id=receipt.paper_id
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM paper_core_conclusion AS conclusion
                        JOIN evidence_fulltext_conclusion_support AS support
                          USING(conclusion_id)
                        WHERE conclusion.paper_id=receipt.paper_id
                    )
                  )
                """,
            ),
            "receipts": _scalar(
                connection, "SELECT count(*) FROM evidence_canonicalization_receipt"
            ),
            "formal_receipts": _scalar(
                connection,
                "SELECT count(*) FROM evidence_canonicalization_receipt WHERE treatment='formal_citation'",
            ),
            "method_receipts": _scalar(
                connection,
                "SELECT count(*) FROM evidence_canonicalization_receipt WHERE treatment='associated_method_origin'",
            ),
            "verified_resource_receipts": _scalar(
                connection,
                "SELECT count(*) FROM evidence_canonicalization_receipt "
                "WHERE resource_mode='verified_local_resource'",
            ),
            "metadata_only_receipts": _scalar(
                connection,
                "SELECT count(*) FROM evidence_canonicalization_receipt "
                "WHERE resource_mode='metadata_only'",
            ),
            "resource_attachments": _scalar(
                connection,
                "SELECT count(*) FROM evidence_canonical_resource_attachment",
            ),
            "method_derivations": _scalar(
                connection,
                "SELECT count(*) FROM evidence_method_origin_candidate_derivation",
            ),
            "associated_method_papers": _scalar(
                connection,
                "SELECT count(DISTINCT paper_id) FROM evidence_associated_method_relation",
            ),
            "associated_method_ledger_occurrences": _scalar(
                connection,
                "SELECT count(DISTINCT ledger_entry_id) FROM evidence_associated_method_relation",
            ),
            "resolved_citation_ledgers": _scalar(
                connection,
                """
                SELECT count(*) FROM citation_binding_projection AS projection
                JOIN citation_binding AS binding USING(binding_id)
                WHERE binding.binding_status='resolved'
                """,
            ),
            "blocked_acquisitions": _scalar(
                connection,
                "SELECT count(*) FROM evidence_acquisition_state WHERE state='blocked'",
            ),
            "fulltext_support": _scalar(
                connection,
                "SELECT count(*) FROM evidence_fulltext_conclusion_support",
            ),
            "formal_binding_mismatches": _scalar(
                connection,
                """
                SELECT count(*)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN paper_clue AS clue
                  ON clue.source_candidate_id=receipt.source_candidate_id
                JOIN citation_ledger_entry AS ledger USING(clue_id)
                LEFT JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                LEFT JOIN citation_binding AS binding USING(binding_id)
                WHERE receipt.treatment='formal_citation'
                  AND (
                    binding.binding_id IS NULL
                    OR binding.binding_status<>'resolved'
                    OR binding.paper_id<>receipt.paper_id
                  )
                """,
            ),
            "formal_receipts_without_ledger": _scalar(
                connection,
                """
                SELECT count(*)
                FROM evidence_canonicalization_receipt AS receipt
                WHERE receipt.treatment='formal_citation'
                  AND NOT EXISTS (
                    SELECT 1
                    FROM paper_clue AS clue
                    JOIN citation_ledger_entry AS ledger USING(clue_id)
                    WHERE clue.source_candidate_id=receipt.source_candidate_id
                  )
                """,
            ),
            "method_relation_mismatches": _scalar(
                connection,
                """
                SELECT count(*)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN paper_clue AS clue
                  ON clue.source_candidate_id=receipt.source_candidate_id
                JOIN citation_ledger_entry AS ledger USING(clue_id)
                LEFT JOIN evidence_associated_method_relation AS relation
                  ON relation.canonicalization_receipt_id=
                     receipt.canonicalization_receipt_id
                 AND relation.ledger_entry_id=ledger.ledger_entry_id
                 AND relation.paper_id=receipt.paper_id
                WHERE receipt.treatment='associated_method_origin'
                  AND relation.associated_relation_id IS NULL
                """,
            ),
            "method_formal_binding_violations": _scalar(
                connection,
                """
                SELECT count(*)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN paper_clue AS clue
                  ON clue.source_candidate_id=receipt.source_candidate_id
                JOIN citation_ledger_entry AS ledger USING(clue_id)
                JOIN citation_binding_projection AS projection USING(ledger_entry_id)
                JOIN citation_binding AS binding USING(binding_id)
                WHERE receipt.treatment='associated_method_origin'
                  AND (
                    binding.binding_status<>'rejected_non_paper'
                    OR binding.paper_id IS NOT NULL
                  )
                """,
            ),
            "method_source_disposition_violations": _scalar(
                connection,
                """
                SELECT count(DISTINCT receipt.canonicalization_receipt_id)
                FROM evidence_canonicalization_receipt AS receipt
                JOIN paper_clue AS clue
                  ON clue.source_candidate_id=receipt.source_candidate_id
                JOIN paper_clue_candidate AS link
                  ON link.clue_id=clue.clue_id AND link.link_kind='local_claim'
                JOIN paper_candidate AS candidate USING(candidate_id)
                WHERE receipt.treatment='associated_method_origin'
                  AND (
                    clue.resolution_status<>'rejected_non_paper'
                    OR candidate.resolution_status<>'rejected_non_paper'
                  )
                """,
            ),
        }
    if integrity != "ok" or foreign_keys:
        raise RuntimeError("isolated total replay failed database integrity checks")
    with evidence_connection(settings) as connection:
        resource_ids = [
            str(row["resource_id"])
            for row in connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id"
            )
        ]
    resource_store = EvidenceResourceStore(settings)
    verified_resource_bytes = 0
    verified_resource_hashes: set[str] = set()
    for resource_id in resource_ids:
        response = resource_store.resource_response(resource_id)
        if response.media_type != "application/pdf" or not response.payload.startswith(
            b"%PDF-"
        ):
            raise RuntimeError(f"resource verification failed: {resource_id}")
        verified_resource_bytes += len(response.payload)
        verified_resource_hashes.add(hashlib.sha256(response.payload).hexdigest())
    dedup_expected_counts = dedup_expectation["expected_counts"]
    assert isinstance(dedup_expected_counts, dict)
    actual_action_counts = {
        "created_new_canonical": sum(
            row["action"] == "created_new_canonical" for row in dedup_rows
        ),
        "reused_baseline": sum(bool(row["baseline_match"]) for row in dedup_rows),
        "reused_incoming": sum(
            row["incoming_duplicate_of"] is not None for row in dedup_rows
        ),
    }
    expected_canonical = int(dedup_expected_counts["canonical_total"])
    expected_resources = (
        baseline_resources
        + len(plan["arxiv_storage_approved"])
        + int(plan["open_pdf_allowed_resources"])
    )
    expected_official_abstracts = baseline_official_abstracts + int(
        plan["arxiv_official_abstracts_verified"]
    ) + int(plan["crossref_official_abstracts_verified"])
    expected_core_conclusions = (
        baseline_core_conclusions
        + int(plan["arxiv_reviewed"])
        + int(plan["crossref_official_abstracts_verified"])
    )
    expected_official_abstract_conclusions = (
        baseline_official_abstract_conclusions
        + len(plan["arxiv_license_blocked"])
        + int(plan["crossref_official_abstracts_verified"])
    )
    observed_release_expectation = {
        "canonical_papers": counts["canonical_papers"],
        "verified_resources": counts["resources"],
        "canonicalization_receipts": counts["receipts"],
        "formal_receipts": counts["formal_receipts"],
        "method_receipts": counts["method_receipts"],
        "blocked_acquisitions": counts["blocked_acquisitions"],
        "associated_method_ledger_occurrences": counts[
            "associated_method_ledger_occurrences"
        ],
        "fulltext_conclusion_support": counts["fulltext_support"],
        "official_abstract_excerpts": counts["official_abstract_excerpts"],
        "reviewed_arxiv_official_abstracts": counts[
            "reviewed_arxiv_official_abstracts"
        ],
        "reviewed_crossref_official_abstracts": counts[
            "reviewed_crossref_official_abstracts"
        ],
        "core_conclusions": counts["core_conclusions"],
        "reviewed_open_pdf_resources": counts["reviewed_open_pdf_resources"],
        "displayable_archive_relation_papers": (
            _frozen_v4_displayable_archive_relation_papers(
                settings.research_papers_database_path
            )
        ),
    }
    if (
        observed_release_expectation
        != reviewed_gate_receipt["release_expectation"]
        or
        len(dedup_rows) != int(dedup_expected_counts["incoming"])
        or actual_action_counts
        != {
            "created_new_canonical": int(
                dedup_expected_counts["created_new_canonical"]
            ),
            "reused_baseline": int(dedup_expected_counts["reused_baseline"]),
            "reused_incoming": int(dedup_expected_counts["reused_incoming"]),
        }
        or int(plan["crossref_eligible"])
        != int(dedup_expected_counts["crossref_incoming"])
        or int(plan["arxiv_reviewed"])
        != int(dedup_expected_counts["arxiv_incoming"])
        or counts["canonical_papers"] != expected_canonical
        or counts["strong_identifier_projection"] != 78
        or counts["resources"] != expected_resources
        or counts["official_abstract_excerpts"] != expected_official_abstracts
        or counts["official_abstract_excerpts_without_resource"]
        != expected_official_abstracts
        or counts["reviewed_arxiv_official_abstracts"]
        != int(plan["arxiv_official_abstracts_verified"])
        or counts["reviewed_crossref_official_abstracts"]
        != int(plan["crossref_official_abstracts_verified"])
        or counts["core_conclusions"] != expected_core_conclusions
        or counts["official_abstract_conclusions"]
        != expected_official_abstract_conclusions
        or counts["metadata_only_receipts_with_official_abstract"]
        != len(plan["arxiv_license_blocked"])
        + int(plan["crossref_official_abstracts_verified"])
        or counts["reviewed_open_pdf_resources"]
        != int(plan["open_pdf_allowed_resources"])
        or counts["reviewed_open_pdf_catalog_links"]
        != int(plan["open_pdf_allowed_resources"])
        or counts["official_abstract_resource_coupling_violations"] != 0
        or counts["blocked_arxiv_official_abstracts"] != 3
        or counts["blocked_arxiv_source_evidence_violations"] != 0
        or counts["receipts"] != int(plan["crossref_eligible"]) + int(plan["arxiv_reviewed"])
        or counts["formal_receipts"] != int(plan["crossref_eligible"]) + int(plan["arxiv_formal_citations"])
        or counts["method_receipts"] != 7
        or counts["verified_resource_receipts"]
        != len(plan["arxiv_storage_approved"])
        or counts["metadata_only_receipts"]
        != counts["receipts"] - len(plan["arxiv_storage_approved"])
        or counts["resource_attachments"] != len(plan["arxiv_storage_approved"])
        or counts["method_derivations"] != 7
        or counts["associated_method_papers"] != 7
        or counts["associated_method_ledger_occurrences"] != 547
        or counts["blocked_acquisitions"]
        != len(plan["arxiv_license_blocked"])
        + len(plan["crossref_fulltext_failed_closed"])
        or counts["fulltext_support"] != len(plan["arxiv_storage_approved"])
        or int(plan["arxiv_hash_anchored_reading_locators"]) != 135
        or len(resource_ids) != counts["resources"]
        or counts["formal_binding_mismatches"] != 0
        or counts["formal_receipts_without_ledger"] != 0
        or counts["method_relation_mismatches"] != 0
        or counts["method_formal_binding_violations"] != 0
        or counts["method_source_disposition_violations"] != 0
    ):
        raise RuntimeError("isolated total replay counts violate the reviewed conservation laws")

    reviewed_gate_receipt_identity = _write_reviewed_gate_receipt(
        settings=settings, receipt=reviewed_gate_receipt
    )
    service = EvidenceReleaseService(settings)
    prepared = service.prepare_candidate()
    prepared_repeat = service.prepare_candidate()

    def inventory_material(value: Any) -> tuple[object, ...]:
        return (
            value.export_id,
            value.source_snapshot_hash,
            value.content_sha256,
            value.bytes,
            value.relative_path,
        )

    if (
        prepared_repeat.created
        or prepared_repeat.evidence_release_id != prepared.evidence_release_id
        or prepared_repeat.candidate_spec != prepared.candidate_spec
        or inventory_material(prepared_repeat.inventory)
        != inventory_material(prepared.inventory)
        or inventory_material(prepared_repeat.candidate_inventory)
        != inventory_material(prepared.candidate_inventory)
    ):
        raise RuntimeError("isolated Evidence release preparation is not idempotent")
    authority = ReleaseAuthority(settings)
    candidate = authority.register_candidate(prepared.candidate_spec)
    decision = authority.record_decision(
        candidate.candidate_id,
        deterministic_gate_hash=stable_sha256(
            "reviewed-total-replay-gate/v1", snapshot_after_second
        ),
        review_set_hash=stable_sha256(
            "reviewed-total-replay-review/v1",
            prepared.candidate_spec.artifact_manifest_hash,
            prepared.candidate_spec.requirements_manifest_hash,
        ),
        reconciliation_hash=stable_sha256(
            "reviewed-total-replay-reconciliation/v1",
            str(counts["canonical_papers"]),
            str(counts["resources"]),
            str(counts["receipts"]),
            str(counts["associated_method_ledger_occurrences"]),
        ),
        verdict="pass",
    )
    certificate = authority.issue_snapshot(
        decision.decision_id,
        requirements_manifest_hash=prepared.candidate_spec.requirements_manifest_hash,
        issuance_key=stable_sha256(
            "reviewed-total-replay-issuance/v1",
            prepared.candidate_spec.artifact_manifest_hash,
        ),
    )
    published = service.publish(prepared, certificate)
    repeated_publish = service.publish(prepared, certificate)
    if repeated_publish.created or repeated_publish.activation_id != published.activation_id:
        raise RuntimeError("isolated total release publication is not idempotent")

    query = EvidenceQueryService(settings)
    catalog = query.list_papers(limit=500)
    by_title = {str(row["title"]): row for row in catalog["papers"]}
    p033 = query.paper_detail(str(by_title["Long Short-Term Memory"]["paper_id"]))
    u055 = query.paper_detail(
        str(by_title["Robust Large Margin Deep Neural Networks"]["paper_id"])
    )
    if (
        p033.get("venue", {}).get("volume") != "9"
        or p033.get("venue", {}).get("issue") != "8"
        or u055["local_resources"]
        or u055["core_conclusions"]
    ):
        raise RuntimeError("P033 metadata or U055 failed-closed API boundary is incorrect")
    rights_probe_ids = {"P034", "P120", "P137", "P143", "P145", "P171"}
    with evidence_connection(settings) as connection:
        rights_probe_papers = {
            str(row["source_candidate_id"]): str(row["paper_id"])
            for row in connection.execute(
                """
                SELECT source_candidate_id,paper_id
                FROM evidence_canonicalization_receipt
                WHERE source_candidate_id IN ('P034','P120','P137','P143','P145','P171')
                ORDER BY source_candidate_id
                """
            )
        }
        p095_receipts = _scalar(
            connection,
            "SELECT count(*) FROM evidence_canonicalization_receipt "
            "WHERE source_candidate_id='P095'",
        )
    if set(rights_probe_papers) != rights_probe_ids or p095_receipts != 0:
        raise RuntimeError("rights probes or P095 fail-closed receipt boundary is incomplete")
    blocked_details = {
        source_id: query.paper_detail(rights_probe_papers[source_id])
        for source_id in ("P034", "P137", "P143")
    }
    approved_details = {
        source_id: query.paper_detail(rights_probe_papers[source_id])
        for source_id in ("P120", "P145", "P171")
    }
    _assert_arxiv_rights_probe_details(blocked_details, approved_details)

    app = create_app(settings, {"TESTING": True})
    client = app.test_client()
    list_html = client.get("/evidence/")
    list_api = client.get("/api/v1/evidence/papers?limit=500")
    p033_api = client.get(f"/api/v1/evidence/papers/{p033['paper_id']}")
    p033_html = client.get(f"/evidence/papers/{p033['paper_id']}")
    if (
        list_html.status_code != 200
        or list_api.status_code != 200
        or p033_api.status_code != 200
        or p033_html.status_code != 200
        or b"9(8)" not in p033_html.data
        or int(list_api.get_json()["data"]["total"]) != counts["canonical_papers"]
    ):
        raise RuntimeError("isolated Evidence web/API acceptance failed")
    with evidence_connection(settings) as connection:
        resource_id = str(
            connection.execute(
                "SELECT resource_id FROM paper_resource ORDER BY resource_id LIMIT 1"
            ).fetchone()[0]
        )
    resource_response = client.get(f"/api/v1/evidence/resources/{resource_id}")
    if resource_response.status_code != 200 or not resource_response.data.startswith(b"%PDF-"):
        raise RuntimeError("isolated Evidence resource API failed")

    _assert_reviewed_gate_stable(
        reviewed_gate_receipt,
        sources=sources,
        plan=plan,
        dedup_expectation=dedup_expectation,
        dedup_identity=dedup_expectation_identity,
        label="pre-freeze verification",
    )

    quiescent_candidate = _freeze_quiescent_candidate(
        settings=settings,
        replay_root=target,
        expected_resources=counts["resources"],
        replay_snapshot_hash=snapshot_after_second,
        gate_receipt_identity=reviewed_gate_receipt_identity,
    )
    _assert_reviewed_gate_stable(
        reviewed_gate_receipt,
        sources=sources,
        plan=plan,
        dedup_expectation=dedup_expectation,
        dedup_identity=dedup_expectation_identity,
        label="post-freeze verification",
    )

    live_after = _database_fingerprint(live_database)
    if live_before != live_after:
        raise RuntimeError("live Evidence database changed during isolated total replay")
    atexit.unregister(verify_live_database_on_failure)

    result = {
        "schema_version": "qrh-reviewed-evidence-total-replay/v1",
        "var_root": str(target),
        "reviewed_input_gate": {
            "receipt": reviewed_gate_receipt,
            "receipt_identity": reviewed_gate_receipt_identity,
            "dedup_expectation_identity": dedup_expectation_identity,
            "stability_checks": [
                "post-apply verification",
                "pre-freeze verification",
                "post-freeze verification",
            ],
        },
        "live_database_before": live_before,
        "live_database_after": live_after,
        "baseline_counts": baseline.counts,
        "static_plan": plan,
        "import_result": first.as_dict(),
        "counts": counts,
        "dedup_summary": {
            "incoming_rows": len(dedup_rows),
            **actual_action_counts,
            "expected_canonical": expected_canonical,
        },
        "dedup_table": dedup_rows,
        "snapshot_after_first": snapshot_after_first,
        "snapshot_after_second": snapshot_after_second,
        "release": {
            "evidence_release_id": prepared.evidence_release_id,
            "prepare_replay_created": prepared_repeat.created,
            "release_snapshot_urn": certificate.snapshot_urn,
            "activation_id": published.activation_id,
            "active_revision": published.active_revision,
            "source_snapshot_hash": prepared.candidate_spec.source_snapshot_hash,
            "artifact_manifest_hash": prepared.candidate_spec.artifact_manifest_hash,
            "requirements_manifest_hash": prepared.candidate_spec.requirements_manifest_hash,
        },
        "web_api": {
            "list_html": list_html.status_code,
            "list_api": list_api.status_code,
            "p033_api": p033_api.status_code,
            "p033_html": p033_html.status_code,
            "resource_api": resource_response.status_code,
            "blocked_resource_probes": sorted(blocked_details),
            "cc_by_resource_probes": sorted(approved_details),
            "p095_receipts": p095_receipts,
        },
        "resource_verification": {
            "database_resources_verified": len(resource_ids),
            "distinct_content_hashes": len(verified_resource_hashes),
            "verified_bytes": verified_resource_bytes,
        },
        "quiescent_candidate": quiescent_candidate,
        "integrity_check": integrity,
        "foreign_key_violations": foreign_keys,
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    result_path = target / "TOTAL_REPLAY_RESULT.json"
    with result_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
