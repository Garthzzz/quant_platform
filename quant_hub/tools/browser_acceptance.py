from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
from contextlib import closing
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import threading
from typing import Any

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

from quant_hub.app import create_app
from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.config import Settings, is_reparse_point
from quant_hub.evidence.presentation import chinese_overlays_by_excerpt
from quant_hub.evidence.service import EvidenceQueryService
from quant_hub.runtime_seal import (
    RuntimeSealError,
    assert_material,
    database_state,
    file_identity as sealed_file_identity,
    read_json,
    runtime_toolchain,
    safe_tree,
)
from quant_hub.web.security import compile_trusted_origins


def _tree(root: Path) -> dict[str, object]:
    return safe_tree(root)


def _file_identity(path: Path) -> dict[str, object]:
    return sealed_file_identity(path)


def _verified_response_sha256(
    headers: Mapping[str, str], payload: bytes
) -> tuple[str, str]:
    """Return a body-bound digest advertised by the HTTP response.

    Evidence resources expose their content digest as a strong ETag.  Archive
    assets additionally expose ``X-Content-SHA256``.  Browser acceptance must
    understand both public contracts and must independently hash the bytes;
    merely checking that a digest-shaped header exists is not sufficient.
    """

    digest = str(headers.get("x-content-sha256", "")).strip().lower()
    source = "x-content-sha256"
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        digest = str(headers.get("etag", "")).strip()
        if digest.startswith("W/"):
            digest = digest[2:].strip()
        digest = digest.strip('"').lower()
        source = "etag"
    actual = hashlib.sha256(payload).hexdigest()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None or digest != actual:
        return "", source
    return digest, source


def _backup_database(source: Path, destination: Path) -> dict[str, object]:
    if source.is_symlink() or is_reparse_point(source) or source.lstat().st_nlink != 1:
        raise RuntimeError(f"database source is unsafe: {source}")
    sidecars = [Path(f"{source}{suffix}") for suffix in ("-wal", "-shm", "-journal")]
    present = [str(path) for path in sidecars if os.path.lexists(path)]
    if present:
        raise RuntimeError(
            "delivery database is not a quiescent snapshot: " + ", ".join(present)
        )
    source_before = _file_identity(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # SQLite 的普通 mode=ro 仍可能为 WAL 数据库在源目录创建 -shm/-wal。
    # 验收只能观察交付物，不能在被验收运行根留下任何介质副作用。
    source_uri = f"file:{source.as_posix()}?mode=ro&immutable=1"
    # sqlite3.Connection 的上下文管理器只处理事务，不会关闭连接；必须显式
    # closing，否则 Windows 上会留下锁与 WAL/SHM sidecar。
    with closing(sqlite3.connect(source_uri, uri=True)) as source_connection:
        with closing(sqlite3.connect(destination)) as destination_connection:
            source_connection.backup(destination_connection)
            destination_connection.commit()
    source_after = _file_identity(source)
    if source_after != source_before or any(os.path.lexists(path) for path in sidecars):
        raise RuntimeError("delivery database changed or gained sidecars during backup")
    return source_after


def _copy_tree_snapshot(source: Path, destination: Path) -> dict[str, object]:
    before = safe_tree(source)
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    after = safe_tree(source)
    copied = safe_tree(destination)
    if before != after or copied != before:
        raise RuntimeSealError(f"managed tree changed or copied inconsistently: {source}")
    return after


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


_PLACEHOLDER_PREFIXES = (
    "暂无",
    "尚无",
    "待核验",
    "未提供",
    "未解析",
    "没有匹配",
    "没有可用",
    "当前公开研究页未解析",
    "missing",
    "none",
    "n/a",
    "not available",
    "placeholder",
)

_DISPLAYABLE_ARCHIVE_RELATION_RECEIPT_FIELD = (
    "displayable_archive_relation_papers"
)


def _normalise_semantic_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value).strip()


def _is_placeholder_text(value: object) -> bool:
    text = _normalise_semantic_text(value).casefold()
    if not text or len(text) > 160:
        return False
    return any(text.startswith(prefix.casefold()) for prefix in _PLACEHOLDER_PREFIXES)


_RESEARCHER_API_FORBIDDEN_KEY_FRAGMENTS = (
    "sha256",
    "provenance",
    "verification",
    "fact_boundary",
    "rights",
    "ledger",
    "urn",
    "canonical_path",
    "locator",
    "metadata_review",
    "reading_task",
    "category",
)


def _researcher_api_internal_keys(value: object) -> list[str]:
    if isinstance(value, Mapping):
        own = [
            str(key)
            for key in value
            if any(
                marker in str(key).casefold()
                for marker in _RESEARCHER_API_FORBIDDEN_KEY_FRAGMENTS
            )
        ]
        nested = [
            key
            for child in value.values()
            for key in _researcher_api_internal_keys(child)
        ]
        return sorted(set(own + nested))
    if isinstance(value, list):
        return sorted(
            {
                key
                for child in value
                for key in _researcher_api_internal_keys(child)
            }
        )
    return []


def _semantic_items_gate(
    items: object,
    *,
    min_text_chars: int,
    href_pattern: str | None = None,
    required_fields: Mapping[str, int] | None = None,
) -> tuple[bool, dict[str, object]]:
    """Fail closed unless every advertised semantic item is visible and real.

    Browser selectors deliberately target elements marked as present.  A section
    heading, an empty node, a placeholder sentence, hidden content or an invalid
    link must therefore fail instead of being counted as product evidence.
    """

    raw_items = items if isinstance(items, list) else []
    audited: list[dict[str, object]] = []
    for index, raw in enumerate(raw_items):
        reasons: list[str] = []
        if not isinstance(raw, Mapping):
            audited.append(
                {
                    "index": index,
                    "valid": False,
                    "reasons": ["invalid-probe-shape"],
                }
            )
            continue
        visible = raw.get("visible") is True
        text = _normalise_semantic_text(raw.get("text"))
        href = _normalise_semantic_text(raw.get("href"))
        if not visible:
            reasons.append("hidden")
        if len(text) < min_text_chars:
            reasons.append("empty-or-too-short")
        elif _is_placeholder_text(text):
            reasons.append("placeholder")
        if href_pattern is not None and re.fullmatch(href_pattern, href) is None:
            reasons.append("invalid-href")
        field_audit: dict[str, dict[str, object]] = {}
        for field, minimum in (required_fields or {}).items():
            field_text = _normalise_semantic_text(raw.get(field))
            field_reasons: list[str] = []
            if len(field_text) < minimum:
                field_reasons.append("empty-or-too-short")
            elif _is_placeholder_text(field_text):
                field_reasons.append("placeholder")
            if field_reasons:
                reasons.append(f"invalid-field:{field}")
            field_audit[field] = {
                "chars": len(field_text),
                "preview": field_text[:120],
                "reasons": field_reasons,
            }
        audited.append(
            {
                "index": index,
                "valid": not reasons,
                "visible": visible,
                "text_chars": len(text),
                "text_preview": text[:160],
                "href": href,
                "fields": field_audit,
                "reasons": reasons,
            }
        )
    valid_count = sum(1 for item in audited if item.get("valid") is True)
    passed = bool(audited) and valid_count == len(audited)
    return passed, {
        "passed": passed,
        "advertised": len(audited),
        "valid": valid_count,
        "invalid": [item for item in audited if item.get("valid") is not True],
    }


_EVIDENCE_CONTENT_CONTRACT: dict[str, dict[str, object]] = {
    "external-original": {
        "min_text_chars": 2,
        "href_pattern": r"https?://\S+",
    },
    "local-original": {
        "min_text_chars": 2,
        "href_pattern": (
            r"(?:/api/v1/evidence/resources/|/evidence/library/)"
            r"[^/?#\s]+"
        ),
    },
    "abstract-evidence": {"min_text_chars": 80},
    "abstract-translation-zh": {"min_text_chars": 40},
    "synthesis-zh": {"min_text_chars": 20},
    "core-conclusions": {"min_text_chars": 20},
    "archive-relations": {
        "min_text_chars": 60,
        "href_pattern": (
            r"/research/[^/?#\s]+/documents/[^?#\s]+"
            r"(?:#(?:document-[^\s#]+|anc_sha256_[0-9a-f]{64}))?"
        ),
        "required_fields": {
            "research_title": 2,
            "document_title": 2,
            "relation_label": 2,
            "usage_description": 10,
            "source_excerpt": 10,
            "source_location": 2,
        },
    },
}


def _validate_evidence_detail_snapshot(
    snapshot: object,
    expectations: object | None = None,
) -> tuple[bool, dict[str, object]]:
    source = snapshot if isinstance(snapshot, Mapping) else {}
    expected_source = expectations if isinstance(expectations, Mapping) else None
    checks: dict[str, dict[str, object]] = {}
    for name, contract in _EVIDENCE_CONTENT_CONTRACT.items():
        expected = (
            expected_source.get(name)
            if expected_source is not None
            else True
        )
        if not isinstance(expected, bool):
            checks[name] = {
                "passed": False,
                "expected": expected,
                "advertised": 0,
                "valid": 0,
                "invalid": [{"reasons": ["invalid-expectation"]}],
            }
            continue
        if not expected:
            raw_items = source.get(name)
            advertised = len(raw_items) if isinstance(raw_items, list) else 0
            checks[name] = {
                "passed": advertised == 0,
                "expected": False,
                "advertised": advertised,
                "valid": 0,
                "invalid": (
                    []
                    if advertised == 0
                    else [{"reasons": ["unexpected-content-when-missing"]}]
                ),
            }
            continue
        passed, evidence = _semantic_items_gate(
            source.get(name),
            min_text_chars=int(contract["min_text_chars"]),
            href_pattern=(
                str(contract["href_pattern"])
                if contract.get("href_pattern") is not None
                else None
            ),
            required_fields=(
                contract.get("required_fields")
                if isinstance(contract.get("required_fields"), Mapping)
                else None
            ),
        )
        evidence["passed"] = passed
        evidence["expected"] = True
        checks[name] = evidence
    passed = all(check["passed"] is True for check in checks.values())
    return passed, {"passed": passed, "checks": checks}


def _forbidden_elements_absent(
    elements: object,
) -> tuple[bool, dict[str, object]]:
    """Count hidden controls too: hiding a forbidden field is still a failure."""

    raw = elements if isinstance(elements, list) else []
    hidden = sum(
        1
        for item in raw
        if isinstance(item, Mapping) and item.get("visible") is not True
    )
    passed = len(raw) == 0
    return passed, {"passed": passed, "found": len(raw), "hidden": hidden}


def _forbidden_phrases_absent(
    markup: object, phrases: tuple[str, ...]
) -> tuple[bool, dict[str, object]]:
    text = markup if isinstance(markup, str) else ""
    found = [phrase for phrase in phrases if phrase and phrase in text]
    passed = not found
    return passed, {"passed": passed, "found": found}


def _validate_research_landing_snapshot(
    snapshot: object,
) -> tuple[bool, dict[str, object]]:
    source = snapshot if isinstance(snapshot, Mapping) else {}
    direct = source.get("direct_content")
    direct_items = direct if isinstance(direct, list) else []
    catalog = source.get("catalog")
    catalog_data = catalog if isinstance(catalog, Mapping) else {}
    catalog_order = catalog_data.get("order")
    catalog_visible = catalog_data.get("visible") is True
    expected_kinds_raw = source.get("expected_featured_kinds")
    expected_kinds = (
        [
            _normalise_semantic_text(item)
            for item in expected_kinds_raw
            if _normalise_semantic_text(item)
        ]
        if isinstance(expected_kinds_raw, list)
        else []
    )
    expected_kinds_valid = (
        bool(expected_kinds)
        and expected_kinds[0] == "overview"
        and len(expected_kinds) == len(set(expected_kinds))
        and set(expected_kinds).issubset({"overview", "review"})
    )
    expected_child_count = source.get("expected_child_count")
    expected_child_count_valid = (
        isinstance(expected_child_count, int) and expected_child_count >= 0
    )
    direct_checks: dict[str, dict[str, object]] = {}
    direct_by_kind: dict[str, list[Mapping[str, object]]] = {}
    for raw in direct_items:
        if isinstance(raw, Mapping):
            kind = _normalise_semantic_text(raw.get("kind"))
            direct_by_kind.setdefault(kind, []).append(raw)
    direct_orders: dict[str, int] = {}
    direct_ids: set[str] = set()
    for kind in expected_kinds:
        candidates = direct_by_kind.get(kind, [])
        passed, evidence = _semantic_items_gate(
            candidates,
            min_text_chars=200,
            required_fields={"document_id": 1},
        )
        if len(candidates) != 1:
            passed = False
            evidence["cardinality"] = len(candidates)
        if len(candidates) == 1:
            order = candidates[0].get("order")
            if isinstance(order, int):
                direct_orders[kind] = order
            document_id = _normalise_semantic_text(candidates[0].get("document_id"))
            if document_id:
                direct_ids.add(document_id)
        evidence["passed"] = passed
        direct_checks[kind] = evidence

    direct_kind_set_exact = (
        expected_kinds_valid
        and set(direct_by_kind) == set(expected_kinds)
        and len(direct_items) == len(expected_kinds)
    )
    order_passed = (
        isinstance(catalog_order, int)
        and set(direct_orders) == set(expected_kinds)
        and [direct_orders[kind] for kind in expected_kinds]
        == sorted(direct_orders.values())
        and all(direct_orders[kind] < catalog_order for kind in expected_kinds)
    )
    children = catalog_data.get("children")
    child_items = children if isinstance(children, list) else []
    if expected_child_count_valid and expected_child_count == 0:
        children_passed = len(child_items) == 0
        children_evidence = {
            "passed": children_passed,
            "advertised": len(child_items),
            "valid": 0,
            "invalid": [],
            "expected": 0,
        }
    else:
        children_passed, children_evidence = _semantic_items_gate(
            child_items,
            min_text_chars=2,
            href_pattern=r"/research/[^/?#\s]+/documents/[^?#\s]+",
            required_fields={"document_id": 1},
        )
        children_passed = (
            children_passed
            and expected_child_count_valid
            and len(child_items) == expected_child_count
        )
        children_evidence["passed"] = children_passed
        children_evidence["expected"] = expected_child_count
    child_ids = {
        _normalise_semantic_text(item.get("document_id"))
        for item in child_items
        if isinstance(item, Mapping)
    }
    child_ids.discard("")
    disjoint = (
        len(direct_ids) == len(expected_kinds)
        and direct_ids.isdisjoint(child_ids)
    )
    forbidden_passed, forbidden_evidence = _forbidden_phrases_absent(
        source.get("markup"), ("最终支持的决策",)
    )
    no_document_projection = source.get("research_document_count") == 0
    passed = (
        expected_kinds_valid
        and expected_child_count_valid
        and direct_kind_set_exact
        and all(check["passed"] is True for check in direct_checks.values())
        and catalog_visible
        and order_passed
        and children_passed
        and disjoint
        and forbidden_passed
        and no_document_projection
    )
    return passed, {
        "passed": passed,
        "expected_featured_kinds": expected_kinds,
        "expected_featured_kinds_valid": expected_kinds_valid,
        "actual_featured_kinds": sorted(direct_by_kind),
        "direct_kind_set_exact": direct_kind_set_exact,
        "expected_child_count": expected_child_count,
        "expected_child_count_valid": expected_child_count_valid,
        "direct_content": direct_checks,
        "catalog_visible": catalog_visible,
        "order_passed": order_passed,
        "orders": {**direct_orders, "catalog": catalog_order},
        "children": children_evidence,
        "direct_document_ids": sorted(direct_ids),
        "child_document_ids": sorted(child_ids),
        "direct_documents_excluded_from_children": disjoint,
        "forbidden_decision_copy": forbidden_evidence,
        "research_document_count": source.get("research_document_count"),
        "no_document_projection": no_document_projection,
    }


def _browser_semantic_items(locator: Any) -> list[dict[str, object]]:
    return locator.evaluate_all(
        """
        nodes => nodes.map(node => {
          const style = getComputedStyle(node);
          const rect = node.getBoundingClientRect();
          const link = node.matches('a[href]') ? node : node.querySelector('a[href]');
          return {
            visible: !node.hidden && node.getAttribute('aria-hidden') !== 'true'
              && style.display !== 'none' && style.visibility !== 'hidden'
              && rect.width > 0 && rect.height > 0,
            text: (node.innerText || node.textContent || '').trim(),
            href: link ? (link.getAttribute('href') || '') : ''
          };
        })
        """
    )


def _database_evidence_content_counts(
    database: Path,
    *,
    chinese_overlay_excerpt_hashes: set[str],
    displayable_archive_relation_papers: int,
) -> dict[str, int]:
    queries = {
        "external-original": (
            "SELECT count(*) FROM paper_catalog_projection "
            "WHERE json_array_length(external_links_json)>0"
        ),
        "local-original": """
            SELECT count(DISTINCT paper_id)
            FROM (
                SELECT paper_id
                FROM paper_resource
                WHERE verification_status='verified' AND paper_id IS NOT NULL
                UNION ALL
                SELECT attachment.paper_id
                FROM evidence_canonical_resource_attachment AS attachment
                JOIN paper_resource AS resource USING(resource_id)
                WHERE resource.verification_status='verified'
            )
        """,
        "abstract-evidence": "SELECT count(DISTINCT paper_id) FROM evidence_excerpt",
        "core-conclusions": (
            "SELECT count(*) FROM paper_catalog_projection "
            "WHERE json_array_length(core_conclusions_json)>0"
        ),
        "core-conclusion-rows": "SELECT count(*) FROM paper_core_conclusion",
    }
    uri = f"file:{database.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        counts = {
            name: int(connection.execute(query).fetchone()[0])
            for name, query in queries.items()
        }
        counts["canonical-papers"] = int(
            connection.execute("SELECT count(*) FROM paper").fetchone()[0]
        )
        counts["official-abstract-excerpts"] = int(
            connection.execute("SELECT count(*) FROM evidence_excerpt").fetchone()[0]
        )
        overlay_paper_ids = {
            str(row[0])
            for row in connection.execute(
                "SELECT paper_id,excerpt_sha256 FROM evidence_excerpt"
            ).fetchall()
            if str(row[1]) in chinese_overlay_excerpt_hashes
        }
    # 展示层资源可能包含其他 release 的合法条目；只有与本候选 DB 当前
    # evidence_excerpt 哈希相交的论文才会由 service 真正显示译文和综述。
    # 直接使用全局 overlay 表长度会把未进入候选的条目误算进本次验收。
    counts["abstract-translation-zh"] = len(overlay_paper_ids)
    counts["synthesis-zh"] = len(overlay_paper_ids)
    counts["archive-relations"] = displayable_archive_relation_papers
    return counts


def _researcher_evidence_content_counts(
    details: Iterable[Mapping[str, object]],
) -> dict[str, int]:
    """Count the effective public dossier contract, one paper at a time.

    The reviewed release receipt deliberately preserves raw evidence-row counts.
    The researcher view may additionally use reviewed enrichment rows and
    historical Archive mappings stored in the same sealed database.  Browser and
    API coverage must therefore be compared with this public projection, while
    ``_validate_database_release_row_counts`` continues to bind the underlying
    raw rows to the release receipt independently.
    """

    counts = {name: 0 for name in _EVIDENCE_CONTENT_CONTRACT}
    for detail in details:
        external_links = detail.get("external_links")
        local_resources = detail.get("local_resources")
        excerpts = detail.get("abstract_excerpts")
        conclusions = detail.get("core_conclusions")
        core_relations = detail.get("archive_core_relations")
        reference_relations = detail.get("archive_reference_relations")
        chinese = detail.get("chinese_presentation")

        if isinstance(external_links, list) and external_links:
            counts["external-original"] += 1
        if isinstance(local_resources, list) and local_resources:
            counts["local-original"] += 1
        if isinstance(excerpts, list) and excerpts:
            counts["abstract-evidence"] += 1
        if isinstance(excerpts, list) and any(
            isinstance(item, Mapping)
            and isinstance(item.get("chinese_presentation"), Mapping)
            and bool(
                str(
                    item["chinese_presentation"].get(
                        "abstract_translation_zh", ""
                    )
                ).strip()
            )
            for item in excerpts
        ):
            counts["abstract-translation-zh"] += 1
        if isinstance(chinese, Mapping) and bool(
            str(chinese.get("synthesis_zh", "")).strip()
        ):
            counts["synthesis-zh"] += 1
        if isinstance(conclusions, list) and conclusions:
            counts["core-conclusions"] += 1
        # ``archive_relations`` is the broader internal candidate pool.  The
        # researcher page deliberately shows only the selected core set, or the
        # formal-reference fallback when no core relation exists.  Count that
        # exact public contract so title-disambiguated backup noise cannot add a
        # phantom database paper that neither the API coverage flag nor the DOM
        # advertises.
        if (
            isinstance(core_relations, list)
            and core_relations
        ) or (
            isinstance(reference_relations, list)
            and reference_relations
        ):
            counts["archive-relations"] += 1
    return counts


def _database_effective_evidence_content_counts(
    settings: Settings,
) -> dict[str, int]:
    """Project the sealed database through the exact public service contract."""

    service = EvidenceQueryService(settings)
    catalogue = service.list_papers(limit=500)
    papers = catalogue.get("papers")
    if not isinstance(papers, list):
        raise RuntimeError("evidence service returned an invalid paper catalogue")
    details = [
        service.researcher_paper_detail(str(paper["paper_id"]))
        for paper in papers
        if isinstance(paper, Mapping) and paper.get("paper_id")
    ]
    if len(details) != catalogue.get("total"):
        raise RuntimeError("effective evidence projection omitted catalogue papers")
    return _researcher_evidence_content_counts(details)


def _displayable_archive_relation_paper_count(
    rows_by_paper: Mapping[str, list[Mapping[str, object]]],
    archive_index: dict[str, dict[str, Any]],
    *,
    paper_titles: Mapping[str, str] | None = None,
) -> int:
    """Project raw relations through the exact public-detail selection contract.

    Raw resolved bindings, method-origin edges and canonical paper totals are not
    display counts.  A paper qualifies only when the service can select either a
    core relation with a valid Archive target URL or, if no core relation exists,
    a linkable formal-reference fallback.
    """

    displayable = 0
    titles = paper_titles or {}
    for paper_id, rows in rows_by_paper.items():
        material = list(rows)
        core_relations, reference_relations, _scope = (
            EvidenceQueryService._select_display_archive_relations(
                material,
                archive_index,
                paper_title=titles.get(paper_id, ""),
            )
        )
        if core_relations or reference_relations:
            displayable += 1
    return displayable


def _database_displayable_archive_relation_papers(settings: Settings) -> int:
    archive_index = ArchiveCatalog(settings).archive_link_index()
    database = settings.research_papers_database_path.resolve(strict=True)
    uri = f"file:{database.as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            WITH relations AS (
                SELECT paper_id,relation_id,research_urn,document_version_urn,
                       citation_id,ledger_entry_id,relation_kind,
                       'formal_or_direct' AS relation_semantics
                FROM research_paper_relation
                UNION ALL
                SELECT association.paper_id,
                       association.associated_relation_id AS relation_id,
                       ledger.research_urn,ledger.document_version_urn,
                       association.citation_id,association.ledger_entry_id,
                       association.association_kind AS relation_kind,
                       'associated_method_origin' AS relation_semantics
                FROM evidence_associated_method_relation AS association
                JOIN citation_ledger_entry AS ledger USING(ledger_entry_id)
            )
            SELECT relations.*,ledger.source_path,ledger.canonical_path,
                   ledger.locator_claim,ledger.occurrence_type,
                   occurrence.line_start,occurrence.line_end,
                   occurrence.context_text,occurrence.raw_marker_text
            FROM relations
            JOIN citation_ledger_entry AS ledger USING(ledger_entry_id)
            JOIN citation_occurrence AS occurrence USING(citation_id)
            ORDER BY relations.paper_id,relations.research_urn,
                     ledger.canonical_path,occurrence.line_start,
                     relations.ledger_entry_id
            """
        ).fetchall()
        paper_titles = {
            str(row["paper_id"]): str(row["title"] or "")
            for row in connection.execute(
                "SELECT paper_id,title FROM paper_catalog_projection"
            ).fetchall()
        }
    rows_by_paper: dict[str, list[Mapping[str, object]]] = {}
    for row in rows:
        rows_by_paper.setdefault(str(row["paper_id"]), []).append(row)
    return _displayable_archive_relation_paper_count(
        rows_by_paper,
        archive_index,
        paper_titles=paper_titles,
    )


def _validate_evidence_aggregate_counts(
    *,
    browser_expected: object,
    browser_valid: object,
    api: object,
    database: object,
    release: object,
) -> tuple[bool, dict[str, object]]:
    sources = {
        "browser_expected": browser_expected,
        "browser_valid": browser_valid,
        "api": api,
        "database": database,
        "release": release,
    }
    keys = tuple(_EVIDENCE_CONTENT_CONTRACT)
    comparisons: dict[str, dict[str, object]] = {}
    for name in keys:
        values = {
            source_name: (
                source.get(name) if isinstance(source, Mapping) else None
            )
            for source_name, source in sources.items()
        }
        valid_values = all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in values.values()
        )
        exact = valid_values and len(set(values.values())) == 1
        comparisons[name] = {
            "passed": exact,
            "values": values,
        }
    passed = all(item["passed"] is True for item in comparisons.values())
    return passed, {"passed": passed, "comparisons": comparisons}


def _validate_database_release_row_counts(
    *,
    database: object,
    release: object,
) -> tuple[bool, dict[str, object]]:
    """Bind storage-row invariants to the sealed release receipt.

    The public catalogue aggregate is deliberately paper-oriented: one paper
    contributes at most once to a visible section.  That projection alone cannot
    detect duplicate or missing underlying excerpt/conclusion rows.  Keep the UI
    comparison, but independently close the storage rows and the service-derived
    overlay/relation projections against receipt fields produced by replay.
    """

    # The receipt's displayable-relation count belongs to its frozen Archive
    # projection.  Current Archive documents are independently versioned; their
    # effective relation coverage is closed below against the activation seal,
    # API and browser rather than compared to the historical projection.
    bindings = {
        "official-abstract-excerpt-rows": (
            "official-abstract-excerpts",
            "official_abstract_excerpts",
        ),
        "core-conclusion-rows": (
            "core-conclusion-rows",
            "core_conclusions",
        ),
        "chinese-overlay-paper-intersection": (
            "abstract-translation-zh",
            "official_abstract_excerpts",
        ),
        "chinese-synthesis-paper-intersection": (
            "synthesis-zh",
            "official_abstract_excerpts",
        ),
    }
    checks: dict[str, dict[str, object]] = {}
    for name, (database_field, release_field) in bindings.items():
        actual = database.get(database_field) if isinstance(database, Mapping) else None
        expected = release.get(release_field) if isinstance(release, Mapping) else None
        valid = all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (actual, expected)
        )
        checks[name] = {
            "passed": valid and actual == expected,
            "database_field": database_field,
            "database": actual,
            "release_field": release_field,
            "release": expected,
        }
    passed = all(check["passed"] is True for check in checks.values())
    return passed, {"passed": passed, "checks": checks}


def _validate_output_paths(
    project: Path, delivery: Path, output: Path
) -> tuple[Path, Path]:
    delivery_boundary = (project / "quant_hub" / "var").resolve(strict=True)
    if delivery == delivery_boundary or not delivery.is_relative_to(delivery_boundary):
        raise RuntimeError("delivery-var must be an existing child of quant_hub/var")
    report_boundary = (project / "project_state" / "gates").resolve(strict=True)
    if output == report_boundary or not output.is_relative_to(report_boundary):
        raise RuntimeError("output-root must be a new child of project_state/gates")
    if output.exists():
        raise FileExistsError(f"output-root already exists: {output}")
    return delivery_boundary, report_boundary


def main() -> int:
    parser = argparse.ArgumentParser(description="Quant Research Hub 真实浏览器端到端验收")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--delivery-var", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--browser-executable",
        type=Path,
        default=Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    )
    parser.add_argument(
        "--minimum-evidence-papers",
        type=int,
        default=1,
        help="最终候选应公开展示的规范论文下限；默认仅要求目录非空。",
    )
    parser.add_argument(
        "--host",
        choices=("localhost",),
        default="localhost",
        help="浏览器验收只使用 localhost，避免把数值回环地址暴露给 Chrome。",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8766,
        help="隔离验收端口；8765 保留给最终正式服务。",
    )
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    if args.port in {8000, 8765} or str(args.port).startswith("50"):
        parser.error("port is reserved or excluded by the local browser contract")
    project = args.project_root.resolve(strict=True)
    archive = (project / "reference" / "archive").resolve(strict=True)
    delivery = args.delivery_var.resolve(strict=True)
    output = args.output_root.resolve(strict=False)
    _validate_output_paths(project, delivery, output)

    activation_path = delivery / "ACTIVATED_DELIVERY_SEAL.json"
    activation = read_json(
        activation_path,
        schema_version="qrh-activated-delivery-seal/v1",
    )
    if activation.get("status") != "PASS":
        raise RuntimeError("delivery activation seal is not PASS")
    if Path(str(activation.get("delivery_var", ""))).resolve(strict=True) != delivery:
        raise RuntimeError("activation seal is bound to a different delivery")

    frozen_code_root = delivery / "runtime_contract" / "code"
    frozen_app_source = frozen_code_root / "src" / "quant_hub"
    frozen_presentation = read_json(
        frozen_app_source / "presentation" / "archive_presentation.json",
        schema_version="qrh-archive-presentation/v1",
    )
    frozen_internal_links = frozen_presentation.get("internal_links")
    if not isinstance(frozen_internal_links, Mapping):
        raise RuntimeError("frozen Archive presentation omits internal_links")
    frozen_assets = frozen_internal_links.get("assets")
    if not isinstance(frozen_assets, Mapping):
        raise RuntimeError("frozen Archive presentation assets must be an object")
    expected_archive_asset_hrefs: set[str] = set()
    for asset in frozen_assets.values():
        if not isinstance(asset, Mapping):
            raise RuntimeError("frozen Archive presentation asset is invalid")
        asset_id = asset.get("asset_id")
        if not isinstance(asset_id, str) or not asset_id:
            raise RuntimeError("frozen Archive presentation asset omits asset_id")
        expected_archive_asset_hrefs.add(f"/api/v1/archive/assets/{asset_id}")
    current_app_source = project / "quant_hub" / "src" / "quant_hub"
    current_source_before = safe_tree(
        current_app_source, exclude_runtime_caches=True
    )
    frozen_source_before = safe_tree(
        frozen_app_source, exclude_runtime_caches=True
    )
    assert_material(
        current_source_before,
        frozen_source_before,
        label="browser-executed app source versus frozen app source",
    )
    runtime_contract = activation.get("runtime_contract")
    if not isinstance(runtime_contract, dict):
        raise RuntimeError("activation seal omits runtime contract")
    assert_material(
        safe_tree(frozen_code_root, exclude_runtime_caches=True),
        runtime_contract.get("code"),
        label="frozen runtime code",
    )
    assert_material(
        runtime_toolchain(),
        runtime_contract.get("toolchain"),
        label="browser runtime toolchain",
    )

    expected_databases = activation.get("databases")
    expected_managed = activation.get("managed_trees")
    if not isinstance(expected_databases, dict) or not isinstance(expected_managed, dict):
        raise RuntimeError("activation seal omits database or managed-tree contract")
    for name in (
        "platform.sqlite3",
        "archive.sqlite3",
        "research_papers.sqlite3",
        "paper_lab.sqlite3",
    ):
        assert_material(
            database_state(delivery / "db" / name),
            expected_databases.get(name),
            label=f"activated database {name}",
        )
    for name in (
        "inbox", "objects", "paper_lab", "replay", "research_papers", "exports"
    ):
        assert_material(
            safe_tree(delivery / name),
            expected_managed.get(name),
            label=f"activated managed tree {name}",
        )

    output.mkdir(parents=True, exist_ok=False)
    screenshots = output / "screenshots"
    screenshots.mkdir()
    var = output / "var"
    source_before = _tree(archive)
    proj2_before = _tree(project / "reference" / "proj2")

    database_names = (
        "platform.sqlite3",
        "archive.sqlite3",
        "research_papers.sqlite3",
        "paper_lab.sqlite3",
    )
    delivery_databases_before: dict[str, dict[str, object]] = {}
    for name in database_names:
        source = delivery / "db" / name
        _check(source.is_file(), f"delivery database is missing: {source}")
        delivery_databases_before[name] = _backup_database(
            source, var / "db" / name
        )
    managed_delivery_before: dict[str, dict[str, object]] = {
        name: safe_tree(delivery / name)
        for name in (
            "inbox", "objects", "paper_lab", "replay", "research_papers", "exports"
        )
    }
    for managed_name in ("objects", "research_papers", "paper_lab", "exports"):
        managed_source = delivery / managed_name
        _check(
            managed_source.is_dir(),
            f"delivery managed root is missing: {managed_source}",
        )
        assert_material(
            _copy_tree_snapshot(managed_source, var / managed_name),
            managed_delivery_before[managed_name],
            label=f"browser clone source {managed_name}",
        )

    frozen_migration_root = (
        delivery / "runtime_contract" / "migrations" / "platform"
    )
    _check(
        frozen_migration_root.is_dir(),
        "delivery is missing its frozen runtime migration contract",
    )
    frozen_migrations_before = _tree(frozen_migration_root.parent)
    assert_material(
        frozen_migrations_before,
        runtime_contract.get("migrations"),
        label="frozen runtime migrations",
    )

    settings = Settings.default(
        project_root=project,
        archive_root=archive,
        var_root=var,
        migration_root=frozen_migration_root,
    )
    reviewed_receipt_path = (
        delivery
        / "research_papers"
        / "exports"
        / "reviewed_total_gate_receipt.json"
    )
    reviewed_receipt = read_json(
        reviewed_receipt_path,
        schema_version="qrh-reviewed-evidence-gate-receipt/v1",
    )
    release_expectation = reviewed_receipt.get("release_expectation")
    if not isinstance(release_expectation, dict):
        raise RuntimeError("reviewed release receipt omits release_expectation")
    sealed_displayable_relation_count = release_expectation.get(
        _DISPLAYABLE_ARCHIVE_RELATION_RECEIPT_FIELD
    )
    if not isinstance(sealed_displayable_relation_count, int) or isinstance(
        sealed_displayable_relation_count, bool
    ):
        raise RuntimeError(
            "reviewed release receipt omits integer "
            + _DISPLAYABLE_ARCHIVE_RELATION_RECEIPT_FIELD
        )
    database_displayable_relation_count = (
        _database_displayable_archive_relation_papers(settings)
    )
    database_content_counts = _database_evidence_content_counts(
        settings.research_papers_database_path,
        chinese_overlay_excerpt_hashes=set(chinese_overlays_by_excerpt()),
        displayable_archive_relation_papers=database_displayable_relation_count,
    )
    effective_database_content_counts = (
        _database_effective_evidence_content_counts(settings)
    )
    activation_evidence = activation.get("evidence")
    activation_counts = (
        activation_evidence.get("counts")
        if isinstance(activation_evidence, Mapping)
        else None
    )
    if not isinstance(activation_counts, Mapping):
        raise RuntimeError("activation seal omits evidence counts")
    # Effective content lives in the activated database whose exact digest was
    # verified above.  Canonical-paper and historical-relation totals also have
    # explicit activation fields; bind those independently instead of pretending
    # raw receipt rows and effective public coverage are the same quantity.
    effective_release_content_counts = dict(effective_database_content_counts)
    effective_release_content_counts["external-original"] = (
        activation_counts.get("canonical_papers")
    )
    effective_release_content_counts["archive-relations"] = (
        activation_counts.get("effective_displayable_archive_relation_papers")
    )
    database_release_passed, database_release_evidence = (
        _validate_database_release_row_counts(
            database=database_content_counts,
            release=release_expectation,
        )
    )
    # 浏览器使用的是隔离 DB 副本，但 migration 必须仍绑定被审核 delivery；
    # 因此不能调用 settings.validate_reviewed_runtime()（它要求 migration 位于
    # isolated var 内），这里已由 activation seal 的 exact path+tree hash 约束。
    app = create_app(settings, {"TESTING": False})
    server = make_server(args.host, args.port, app, threaded=True)
    base = f"http://{args.host}:{server.server_port}"
    app.config["TRUSTED_ORIGINS"] = (base,)
    app.extensions["trusted_origins"] = compile_trusted_origins((base,))
    thread = threading.Thread(target=server.serve_forever, name="qrh-browser-acceptance", daemon=True)
    thread.start()
    checks: list[dict[str, object]] = []
    console_errors: list[str] = []
    server_errors: list[dict[str, object]] = []

    def record(name: str, passed: bool, evidence: Any) -> None:
        checks.append({"name": name, "passed": passed, "evidence": evidence})
        _check(passed, f"browser check failed: {name}: {evidence}")

    try:
        record(
            "evidence-database-release-storage-counts-exact",
            database_release_passed,
            database_release_evidence,
        )
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                executable_path=str(args.browser_executable.resolve(strict=True)),
            )
            context = browser.new_context(viewport={"width": 1440, "height": 900}, locale="zh-CN")
            page = context.new_page()
            page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            page.on(
                "response",
                lambda response: server_errors.append(
                    {"status": response.status, "url": response.url}
                )
                if response.status >= 500
                else None,
            )

            page.goto(base + "/", wait_until="networkidle")
            page.screenshot(path=str(screenshots / "01-home-desktop.png"), full_page=True)
            home_title = page.locator("h1").inner_text().strip()
            record("home-title", len(home_title) >= 6, home_title)
            activity_lane_count = page.locator("[data-dashboard-activity] #recent-updates-title").count()
            activity_run_count = page.locator("[data-dashboard-activity] [data-research-update]").count()
            record(
                "dashboard-recent-activity-visible",
                activity_lane_count == 1 and 0 <= activity_run_count <= 3,
                {"activity_lanes": activity_lane_count, "activity_runs": activity_run_count},
            )
            record(
                "dashboard-published-lane-retired",
                page.locator("#completed-title").count() == 0,
                page.locator("#completed-title").count(),
            )
            manual_column_count = page.locator("#active-title, #paused-title").count()
            record(
                "dashboard-three-peer-columns",
                manual_column_count == 2 and activity_lane_count == 1,
                {"manual_columns": manual_column_count, "activity_columns": activity_lane_count},
            )
            manual_card_count = page.locator("#active-title, #paused-title").evaluate_all(
                "headings => headings.reduce((count, heading) => count + heading.closest('section').querySelectorAll('.topic-card').length, 0)"
            )
            non_manual_card_count = page.locator("#active-title, #paused-title").evaluate_all(
                "headings => headings.reduce((count, heading) => count + heading.closest('section').querySelectorAll('.topic-card:not([data-source-kind=manual])').length, 0)"
            )
            record(
                "dashboard-manual-columns-only",
                non_manual_card_count == 0,
                {"manual_cards": manual_card_count, "non_manual_cards": non_manual_card_count},
            )
            header_style = page.locator(".site-header").evaluate(
                "element => ({position: getComputedStyle(element).position, top: getComputedStyle(element).top})"
            )
            record("site-header-sticky", header_style == {"position": "sticky", "top": "0px"}, header_style)
            nav_labels = page.locator(".site-header nav a").all_inner_texts()
            record("global-nav-hides-api", "API" not in nav_labels, nav_labels)
            record("home-has-research", page.locator(".research-index article a").count() > 0, page.locator(".research-index article a").count())
            record("research-cards-hide-status-axes", page.locator(".research-index .axis-list--compact").count() == 0, page.locator(".research-index .axis-list--compact").count())
            home_desktop_widths = page.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("desktop-home-no-body-overflow", home_desktop_widths["scroll"] <= home_desktop_widths["client"] + 1, home_desktop_widths)
            page.keyboard.press("Tab")
            record("skip-link-keyboard", page.locator(".skip-link").evaluate("element => element === document.activeElement"), "first Tab focuses skip link")

            home_decision_passed, home_decision_evidence = (
                _forbidden_phrases_absent(
                    page.content(), ("最终支持的决策",)
                )
            )
            record(
                "home-forbidden-final-decision-copy-absent",
                home_decision_passed,
                home_decision_evidence,
            )
            topic_create_forms = page.locator("[data-topic-create]")
            record(
                "dashboard-flat-create-forms-present",
                topic_create_forms.count() == 2,
                topic_create_forms.count(),
            )
            parent_controls = _browser_semantic_items(
                topic_create_forms.locator('[name="parent_topic_id"]')
            )
            parent_controls_passed, parent_controls_evidence = (
                _forbidden_elements_absent(parent_controls)
            )
            record(
                "dashboard-create-has-no-parent-control-even-hidden",
                parent_controls_passed,
                parent_controls_evidence,
            )
            topic_create_markup = topic_create_forms.evaluate_all(
                "forms => forms.map(form => form.outerHTML).join('\\n')"
            )
            parent_copy_passed, parent_copy_evidence = _forbidden_phrases_absent(
                topic_create_markup, ("父议题",)
            )
            record(
                "dashboard-create-has-no-parent-copy",
                parent_copy_passed,
                parent_copy_evidence,
            )

            topic_stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S%f")
            topic_title = f"浏览器验收研究-{topic_stamp}"
            planned_create = page.locator(
                '[data-topic-create][data-initial-state="planned"]'
            )
            planned_create.evaluate(
                "form => { const panel = form.closest('details'); if (panel) panel.open = true; }"
            )
            planned_create.locator('input[name="title"]').fill(topic_title)
            planned_create.locator('textarea[name="note"]').fill(
                "验证新增研究是无需父议题的独立研究记录。"
            )
            with page.expect_navigation(wait_until="networkidle"):
                planned_create.locator('button[type="submit"]').click()
            topic_card = page.locator("[data-topic-managed]").filter(
                has_text=topic_title
            )
            record(
                "dashboard-manual-flat-create",
                topic_card.count() == 1,
                topic_card.count(),
            )

            topic_card.locator("details.topic-maintenance").evaluate(
                "element => element.open = true"
            )
            topic_edit = topic_card.locator("[data-topic-edit]")
            topic_edit.locator('select[name="state"]').select_option("paused")
            topic_edit.locator(
                'input[name="actor_kind"][value="other"]'
            ).check()
            topic_edit.locator('input[name="display_name"]').fill("验收研究员")
            with page.expect_navigation(wait_until="networkidle"):
                topic_edit.locator('button[type="submit"]').click()
            paused_section = page.locator("#paused-title").locator("xpath=../..")
            moved_topic = paused_section.locator("[data-topic-managed]").filter(
                has_text=topic_title
            )
            record(
                "dashboard-manual-state-move",
                moved_topic.count() == 1
                and "验收研究员" in moved_topic.inner_text(),
                moved_topic.inner_text() if moved_topic.count() else "missing",
            )
            page.screenshot(
                path=str(screenshots / "01b-dashboard-manual-flat.png"),
                full_page=True,
            )

            moved_topic.locator("details.topic-maintenance").evaluate(
                "element => element.open = true"
            )
            page.once("dialog", lambda dialog: dialog.accept())
            with page.expect_navigation(wait_until="networkidle"):
                moved_topic.locator("[data-topic-delete]").click()
            record(
                "dashboard-manual-flat-delete",
                page.locator("[data-topic-managed]").filter(
                    has_text=topic_title
                ).count()
                == 0,
                "soft deleted and removed from active projection",
            )

            research_hrefs = page.locator(".research-index article a").evaluate_all(
                "links => [...new Set(links.map(link => link.getAttribute('href')).filter(Boolean))]"
            )
            q5_card = page.locator(".research-index article").filter(has_text="低信噪比因子序列表征")
            q5_href = q5_card.locator("a").first.get_attribute("href") if q5_card.count() else None
            record("q5-sequence-representation-discovered", bool(q5_href), q5_href or "none")
            q2_card = page.locator(".research-index article").filter(has_text="低信噪比选股模型训练体系")
            q2_href = q2_card.locator("a").first.get_attribute("href") if q2_card.count() else None
            record("q2-training-factory-discovered", bool(q2_href), q2_href or "none")
            document_hrefs: list[str] = []
            document_landings: dict[str, str] = {}
            q5_document_hrefs: list[str] = []
            landing_contract_errors: list[dict[str, object]] = []
            for candidate_href in research_hrefs:
                page.goto(base + str(candidate_href), wait_until="networkidle")
                direct_content = page.locator("[data-research-direct-content]")
                direct_snapshot = direct_content.evaluate_all(
                    """
                    nodes => {
                      const sequence = [...document.querySelectorAll(
                        '[data-research-direct-content], [data-research-document-links]'
                      )];
                      return nodes.map(node => {
                        const body = node.querySelector('.research-body');
                        const style = body ? getComputedStyle(body) : null;
                        const rect = body ? body.getBoundingClientRect() : null;
                        return {
                          kind: node.getAttribute('data-research-direct-content') || '',
                          document_id: node.getAttribute('data-document-id') || '',
                          visible: Boolean(body && !body.hidden
                            && body.getAttribute('aria-hidden') !== 'true'
                            && style.display !== 'none' && style.visibility !== 'hidden'
                            && rect.width > 0 && rect.height > 0),
                          text: body ? (body.innerText || body.textContent || '').trim() : '',
                          href: '',
                          order: sequence.indexOf(node)
                        };
                      });
                    }
                    """
                )
                catalog = page.locator("[data-research-document-links]")
                catalog_probe = _browser_semantic_items(catalog)
                catalog_order = (
                    catalog.evaluate(
                        """
                        element => [...document.querySelectorAll(
                          '[data-research-direct-content], [data-research-document-links]'
                        )].indexOf(element)
                        """
                    )
                    if catalog.count() == 1
                    else None
                )
                child_snapshot = catalog.locator(
                    "[data-document-id] > a[href]"
                ).evaluate_all(
                    """
                    nodes => nodes.map(node => {
                      const style = getComputedStyle(node);
                      const rect = node.getBoundingClientRect();
                      return {
                        visible: !node.hidden && node.getAttribute('aria-hidden') !== 'true'
                          && style.display !== 'none' && style.visibility !== 'hidden'
                          && rect.width > 0 && rect.height > 0,
                        text: (node.innerText || node.textContent || '').trim(),
                        href: node.getAttribute('href') || '',
                        document_id: node.closest('[data-document-id]')?.getAttribute('data-document-id') || ''
                      };
                    })
                    """
                )
                landing_root = page.locator("[data-research-landing]")
                expected_kinds_value = (
                    landing_root.get_attribute("data-expected-featured-kinds")
                    if landing_root.count() == 1
                    else None
                )
                expected_child_value = (
                    landing_root.get_attribute("data-expected-child-count")
                    if landing_root.count() == 1
                    else None
                )
                expected_featured_kinds = [
                    item.strip()
                    for item in (expected_kinds_value or "").split(",")
                    if item.strip()
                ]
                expected_child_count = (
                    int(expected_child_value)
                    if expected_child_value is not None
                    and re.fullmatch(r"[0-9]+", expected_child_value)
                    else None
                )
                landing_passed, landing_evidence = (
                    _validate_research_landing_snapshot(
                        {
                            "expected_featured_kinds": expected_featured_kinds,
                            "expected_child_count": expected_child_count,
                            "direct_content": direct_snapshot,
                            "catalog": {
                                "visible": (
                                    len(catalog_probe) == 1
                                    and catalog_probe[0].get("visible") is True
                                ),
                                "order": catalog_order,
                                "children": child_snapshot,
                            },
                            "markup": page.content(),
                            "research_document_count": page.locator(
                                ".research-document"
                            ).count(),
                        }
                    )
                )
                if not landing_passed:
                    landing_contract_errors.append(
                        {
                            "landing": str(candidate_href),
                            "evidence": landing_evidence,
                        }
                    )
                if candidate_href == q2_href:
                    pipeline = page.locator("[data-q2-interactive-pipeline]")
                    pipeline_links = pipeline.locator("a[href]")
                    first_overview_child_id = page.locator(
                        ".overview-column > :first-child"
                    ).get_attribute("id")
                    record(
                        "q2-interactive-pipeline-is-first",
                        pipeline.count() == 1
                        and first_overview_child_id == "q2-training-pipeline",
                        {
                            "pipelines": pipeline.count(),
                            "first_child_id": first_overview_child_id,
                        },
                    )
                    record(
                        "q2-pipeline-topology-complete",
                        pipeline_links.count() >= 30
                        and pipeline.locator("text=D1 预处理").count() > 0
                        and pipeline.locator("text=D2").count() > 0
                        and pipeline.locator("text=D10").count() > 0
                        and pipeline.locator("text=D11").count() > 0
                        and pipeline.locator("#q2-backward").count() == 1
                        and pipeline.locator("#q2-temperature-triangle").count() == 1
                        and pipeline.locator("#q2-cross-step-coverage").count() == 1,
                        {"interactive_links": pipeline_links.count()},
                    )
                    record(
                        "q2-standalone-pipeline-document-retired",
                        page.locator(
                            "[data-research-document-links]"
                        ).filter(
                            has_text="低信噪比选股训练管线：数据流、反向传播与跨步骤约束"
                        ).count()
                        == 0,
                        "pipeline source is absent from the public document catalog",
                    )
                    q2_widths = page.evaluate(
                        "({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})"
                    )
                    record(
                        "q2-pipeline-no-body-overflow",
                        q2_widths["scroll"] <= q2_widths["client"] + 1,
                        q2_widths,
                    )
                    leading_metadata = page.locator(
                        '[data-research-direct-content] .research-body > h1:first-child + p'
                    ).all_inner_texts()
                    record(
                        "q2-reader-metadata-date-only",
                        all(
                            not re.match(r"^\s*(?:作者|版本|与\s*v[0-9])", text)
                            for text in leading_metadata
                        ),
                        leading_metadata,
                    )
                    page.screenshot(
                        path=str(screenshots / "02a-q2-interactive-pipeline.png"),
                        full_page=False,
                    )
                direct_links = direct_content.locator(
                    ".direct-content-header a[href]"
                ).evaluate_all(
                    "nodes => nodes.map(node => node.getAttribute('href')).filter(Boolean)"
                )
                links = [
                    str(href)
                    for href in [
                        *direct_links,
                        *(item.get("href") for item in child_snapshot),
                    ]
                    if href
                ]
                # 长文被拆成章节后，受控资源、内部研究链接和图示可能位于
                # 任意章节，而不再必然出现在每份文档的首章。浏览器验收必须
                # 巡检 landing 明确公开的全部章节；只检查 featured/首章会把
                # “内容仍可达”误判成“资源消失”，也会漏过后续章节的坏链接。
                links.extend(
                    str(href)
                    for href in page.locator(
                        '.chapter-navigation-group a[href*="/chapters/"]'
                    ).evaluate_all(
                        "nodes => nodes.map(node => node.getAttribute('href')).filter(Boolean)"
                    )
                    if href
                )
                for href in dict.fromkeys(links):
                    document_href = str(href)
                    if document_href not in document_landings:
                        document_hrefs.append(document_href)
                        document_landings[document_href] = str(candidate_href)
                    if candidate_href == q5_href:
                        q5_document_hrefs.append(document_href)
            record(
                "research-landing-direct-content-contract",
                not landing_contract_errors and len(document_hrefs) > 0,
                {"document_pages": len(document_hrefs), "errors": landing_contract_errors},
            )
            research_href: str | None = None
            for candidate_href in document_hrefs:
                page.goto(base + str(candidate_href), wait_until="networkidle")
                if (
                    page.locator(".citation-trigger").count() > 0
                    and len(page.locator(".research-body").first.inner_text()) > 500
                    and page.locator(".research-document").count() == 1
                ):
                    research_href = str(candidate_href)
                    break
            record(
                "research-citation-candidate",
                research_href is not None,
                research_href or "none",
            )
            assert research_href is not None
            page.screenshot(path=str(screenshots / "02-research-long-form.png"), full_page=True)
            body_text_length = len(page.locator(".research-body").first.inner_text())
            record("research-long-form", body_text_length > 500, body_text_length)
            record("research-toc", page.locator(".toc-panel a").count() > 0, page.locator(".toc-panel a").count())
            citation_count = page.locator(".citation-trigger").count()
            record("research-citations-present", citation_count > 0, citation_count)
            page.locator(".citation-trigger").first.click()
            page.locator("#citation-dialog[open]").wait_for(state="visible")
            expect(page.locator("[data-citation-status]")).to_contain_text("已加载")
            record("citation-dialog-trace", page.locator(".citation-entry").count() > 0, page.locator(".citation-entry").count())
            page.screenshot(path=str(screenshots / "03-citation-dialog.png"), full_page=True)
            page.locator("[data-citation-close]").click()
            page.wait_for_url(lambda url: "cite=" not in str(url))
            record(
                "citation-focus-return",
                page.locator(".citation-trigger").first.evaluate("element => element === document.activeElement"),
                "close restores focus to the citation trigger",
            )

            research_landing_href = document_landings[research_href]
            page.goto(base + research_landing_href, wait_until="networkidle")
            comment_text = f"浏览器验收评论-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
            create_form = page.locator("[data-comment-create]")
            create_form.locator('textarea[name="content"]').fill(comment_text)
            with page.expect_navigation(wait_until="networkidle"):
                create_form.locator('button[type="submit"]').click()
            comment_card = page.locator(".comment-card").filter(has_text=comment_text)
            record("comment-create-persisted", comment_card.count() == 1, comment_card.count())

            comment_card.locator("details").evaluate("element => element.open = true")
            edit_form = comment_card.locator("[data-comment-edit]")
            edited_comment = comment_text + "-已修订"
            edit_form.locator('select[name="actor_kind"]').select_option("song_dingkun")
            edit_form.locator('textarea[name="content"]').fill(edited_comment)
            with page.expect_navigation(wait_until="networkidle"):
                edit_form.locator('button[type="submit"]').click()
            comment_card = page.locator(".comment-card").filter(has_text=edited_comment)
            record(
                "comment-edit-persisted",
                comment_card.count() == 1
                and "张正泽" in comment_card.inner_text()
                and "revision 2" in comment_card.inner_text(),
                comment_card.inner_text() if comment_card.count() else "missing",
            )

            comment_card.locator("details").evaluate("element => element.open = true")
            page.once("dialog", lambda dialog: dialog.accept())
            with page.expect_navigation(wait_until="networkidle"):
                comment_card.locator("[data-comment-delete]").click()
            record("comment-delete-persisted", page.locator(".comment-card").filter(has_text=edited_comment).count() == 0, "deleted")

            assert q5_href is not None
            record(
                "q5-independent-document-pages",
                len(q5_document_hrefs) > 0,
                q5_document_hrefs,
            )
            total_display_math = 0
            total_invalid_math = 0
            total_formula_headings = 0
            raw_display_delimiters: list[dict[str, object]] = []
            missing_toc_targets: list[dict[str, object]] = []
            target_formula_href: str | None = None
            target_formula_index: int | None = None
            for q5_document_href in q5_document_hrefs:
                page.goto(base + q5_document_href, wait_until="networkidle")
                display_math = page.locator(
                    '.research-body .math-display[data-math-rendered="mathml"]'
                )
                total_display_math += display_math.count()
                total_invalid_math += page.locator(".research-body .math-invalid").count()
                total_formula_headings += page.locator(
                    ".research-body h1, .research-body h2, .research-body h3, "
                    ".research-body h4, .research-body h5, .research-body h6"
                ).evaluate_all(
                    "headings => headings.filter(heading => heading.textContent.includes('$$')).length"
                )
                raw_matches = page.locator(".research-body").evaluate(
                    """root => {
                        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
                        const matches = [];
                        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
                            if (!node.nodeValue.includes('$$')) continue;
                            if (node.parentElement?.closest('code, pre, .math-invalid')) continue;
                            matches.push(node.nodeValue.trim().slice(0, 120));
                        }
                        return matches;
                    }"""
                )
                if raw_matches:
                    raw_display_delimiters.append(
                        {"page": q5_document_href, "matches": raw_matches}
                    )
                missing_targets = page.locator(
                    '.document-toc-tree a[href^="#"]'
                ).evaluate_all(
                    """links => links
                        .map(link => decodeURIComponent(link.hash.slice(1)))
                        .filter(identifier => !document.getElementById(identifier))"""
                )
                if missing_targets:
                    missing_toc_targets.append(
                        {"page": q5_document_href, "targets": missing_targets}
                    )
                if target_formula_href is None:
                    target_indices = display_math.evaluate_all(
                        "nodes => nodes.map((node, index) => [node.dataset.tex || '', index])"
                        ".filter(([tex]) => tex.includes('x_{i,f,t-L+1:t}')).map(([, index]) => index)"
                    )
                    if target_indices:
                        target_formula_href = q5_document_href
                        target_formula_index = int(target_indices[0])
            record("q5-display-math-complete", total_display_math == 361, total_display_math)
            record("q5-no-invalid-math", total_invalid_math == 0, total_invalid_math)
            record(
                "q5-no-formula-setext-headings",
                total_formula_headings == 0,
                total_formula_headings,
            )
            record(
                "q5-no-raw-display-delimiters",
                raw_display_delimiters == [],
                raw_display_delimiters,
            )
            record("q5-toc-targets-resolve", missing_toc_targets == [], missing_toc_targets)
            record(
                "q5-reported-sequence-formula-mathml",
                target_formula_href is not None and target_formula_index is not None,
                {"page": target_formula_href, "index": target_formula_index},
            )
            assert target_formula_href is not None and target_formula_index is not None
            page.goto(base + target_formula_href, wait_until="networkidle")
            target_formula = page.locator(
                '.research-body .math-display[data-math-rendered="mathml"]'
            ).nth(target_formula_index)
            target_formula.scroll_into_view_if_needed()
            math_overflow = target_formula.evaluate("element => getComputedStyle(element).overflowX")
            record("q5-math-local-overflow", math_overflow in {"auto", "scroll"}, math_overflow)
            page.screenshot(path=str(screenshots / "04-q5-sequence-formula.png"), full_page=False)

            relative_archive_hrefs: list[dict[str, str]] = []
            missing_internal_states: list[dict[str, str]] = []
            unresolved_internal_links: list[dict[str, str]] = []
            projection_fallbacks: list[str] = []
            archive_asset_hrefs: set[str] = set()
            for candidate_href in document_hrefs:
                page.goto(base + str(candidate_href), wait_until="networkidle")
                # landing 为控制首屏体积只暴露每份文档的入口章；进入入口章后，
                # 左侧文档目录才公开同一文档的全部兄弟章节。把这些真实可达页
                # 追加到当前遍历队列，形成 landing -> 文档 -> 章节的两层闭包。
                # Python 的 list 迭代会继续消费尾部新增项，document_landings
                # 同时充当全局去重集合，避免目录互链造成循环。
                for sibling_href in page.locator(
                    '.chapter-navigation-group a[href*="/chapters/"]'
                ).evaluate_all(
                    "nodes => nodes.map(node => node.getAttribute('href')).filter(Boolean)"
                ):
                    sibling = str(sibling_href)
                    if sibling not in document_landings:
                        document_hrefs.append(sibling)
                        document_landings[sibling] = document_landings[str(candidate_href)]
                for item in page.locator(".research-body a").evaluate_all(
                    """links => links.map(link => ({
                        href: link.getAttribute('href') || '',
                        className: link.className || '',
                        state: link.getAttribute('data-internal-link-state') || '',
                        text: link.textContent.trim(),
                    }))"""
                ):
                    href = str(item["href"])
                    if href and not (
                        href.startswith(("/", "#"))
                        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", href)
                    ):
                        relative_archive_hrefs.append(
                            {"page": str(candidate_href), "href": href}
                        )
                    if "archive-internal-link" in str(item["className"]).split():
                        if not item["state"]:
                            missing_internal_states.append(
                                {"page": str(candidate_href), "href": href}
                            )
                        if item["state"] == "unresolved":
                            unresolved_internal_links.append(
                                {"page": str(candidate_href), "href": href}
                            )
                        if href.startswith("/api/v1/archive/assets/"):
                            archive_asset_hrefs.add(href)
                if page.locator(".integrity-warning").count():
                    projection_fallbacks.append(str(candidate_href))
            record("archive-no-browser-relative-links", relative_archive_hrefs == [], relative_archive_hrefs)
            record("archive-internal-links-have-state", missing_internal_states == [], missing_internal_states)
            record("archive-no-unresolved-public-links", unresolved_internal_links == [], unresolved_internal_links)
            record("archive-no-document-projection-fallback", projection_fallbacks == [], projection_fallbacks)
            record(
                "archive-controlled-assets-discovered",
                archive_asset_hrefs == expected_archive_asset_hrefs,
                {
                    "expected": sorted(expected_archive_asset_hrefs),
                    "observed": sorted(archive_asset_hrefs),
                },
            )
            asset_results: list[dict[str, object]] = []
            for asset_href in sorted(archive_asset_hrefs):
                response = context.request.get(base + asset_href)
                asset_results.append(
                    {
                        "href": asset_href,
                        "status": response.status,
                        "bytes": len(response.body()),
                        "sha256": response.headers.get("x-content-sha256", ""),
                    }
                )
            invalid_asset_results = [
                item
                for item in asset_results
                if item["status"] != 200
                or int(item["bytes"]) <= 0
                or re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])) is None
            ]
            record(
                "archive-controlled-assets-verified",
                len(asset_results) == len(expected_archive_asset_hrefs)
                and not invalid_asset_results,
                {"results": asset_results, "invalid": invalid_asset_results},
            )

            diagram_href: str | None = None
            for candidate_href in document_hrefs:
                page.goto(base + str(candidate_href), wait_until="networkidle")
                if page.locator(".ascii-diagram[data-ascii-diagram='enhanced']").count() > 0:
                    diagram_href = str(candidate_href)
                    break
            record("research-ascii-diagram-found", diagram_href is not None, diagram_href or "none")
            diagram = page.locator(".ascii-diagram[data-ascii-diagram='enhanced']").first
            record("ascii-default-svg", diagram.locator("svg.diagram-svg").count() == 1 and diagram.locator("svg.diagram-svg").is_visible(), diagram.locator("svg.diagram-svg").count())
            original_details = diagram.locator("details.ascii-diagram__original")
            raw_length = original_details.locator("code").evaluate("element => element.textContent.length")
            recorded_length = int(diagram.get_attribute("data-source-length") or "-1")
            record("ascii-original-lossless-and-reachable", raw_length == recorded_length and original_details.locator("summary").inner_text() == "查看原始 ASCII", {"raw_length": raw_length, "recorded_length": recorded_length})
            original_details.locator("summary").click()
            record("ascii-original-visible", original_details.locator("code").is_visible(), original_details.get_attribute("open"))
            reading_font = page.locator(".research-body").first.evaluate("element => getComputedStyle(element).fontFamily")
            record("research-font-noto-sans-sc", "Noto Sans SC" in reading_font, reading_font)
            record(
                "research-font-loaded",
                page.evaluate("document.fonts.check('16px \\\"Noto Sans SC\\\"')"),
                "Noto Sans SC",
            )
            expand_button = diagram.locator(".ascii-diagram__actions button").last
            expand_button.click()
            record(
                "ascii-expanded-view",
                "is-expanded" in (diagram.get_attribute("class") or "")
                and expand_button.get_attribute("aria-pressed") == "true",
                diagram.get_attribute("class"),
            )
            page.keyboard.press("Escape")
            record(
                "ascii-expanded-focus-return",
                "is-expanded" not in (diagram.get_attribute("class") or "")
                and expand_button.evaluate("element => element === document.activeElement"),
                diagram.get_attribute("class"),
            )
            diagram_widths = page.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("desktop-diagram-no-body-overflow", diagram_widths["scroll"] <= diagram_widths["client"] + 1, diagram_widths)
            page.screenshot(path=str(screenshots / "07-diagram-desktop.png"), full_page=True)

            page.goto(base + "/evidence/", wait_until="networkidle")
            evidence_count = page.locator(".evidence-paper-card").count()
            record(
                "evidence-catalogue",
                evidence_count >= args.minimum_evidence_papers,
                {
                    "displayed": evidence_count,
                    "required_minimum": args.minimum_evidence_papers,
                },
            )
            evidence_detail_hrefs = page.locator(
                ".evidence-paper-card h2 a[href]"
            ).evaluate_all(
                "nodes => [...new Set(nodes.map(node => node.getAttribute('href')).filter(Boolean))]"
            )
            evidence_api_response = context.request.get(
                base + "/api/v1/evidence/papers?limit=500"
            )
            evidence_api_payload = (
                evidence_api_response.json()
                if evidence_api_response.status == 200
                else {}
            )
            evidence_api_catalog = (
                evidence_api_payload.get("data", {})
                if isinstance(evidence_api_payload, dict)
                else {}
            )
            record(
                "evidence-catalogue-api-sealed-effective-exact",
                evidence_api_response.status == 200
                and evidence_count
                == len(evidence_detail_hrefs)
                == evidence_api_catalog.get("total")
                == effective_database_content_counts["external-original"]
                == effective_release_content_counts["external-original"]
                and evidence_api_catalog.get("coverage", {}).get(
                    "papers_with_user_facing_local_pdfs"
                )
                == effective_database_content_counts["local-original"]
                == effective_release_content_counts["local-original"],
                {
                    "status": evidence_api_response.status,
                    "dom_papers": evidence_count,
                    "detail_hrefs": len(evidence_detail_hrefs),
                    "api_total": evidence_api_catalog.get("total"),
                    "api_local_papers": evidence_api_catalog.get(
                        "coverage", {}
                    ).get("papers_with_user_facing_local_pdfs"),
                    "effective_database": effective_database_content_counts,
                    "effective_release": effective_release_content_counts,
                    "raw_database": database_content_counts,
                    "raw_release_expectation": release_expectation,
                },
            )
            complete_evidence_href: str | None = None
            complete_evidence_snapshot: dict[str, object] | None = None
            complete_evidence_validation: dict[str, object] | None = None
            semantic_failures: list[dict[str, object]] = []
            layout_failures: list[dict[str, object]] = []
            researcher_contract_leaks: list[dict[str, object]] = []
            semantic_coverage = {
                name: {"expected": 0, "valid": 0}
                for name in _EVIDENCE_CONTENT_CONTRACT
            }
            browser_status_counts = {
                name: 0 for name in _EVIDENCE_CONTENT_CONTRACT
            }
            api_content_counts = {
                name: 0 for name in _EVIDENCE_CONTENT_CONTRACT
            }
            for candidate_href in evidence_detail_hrefs:
                page.goto(base + str(candidate_href), wait_until="networkidle")
                visible_detail_text = page.locator("body").inner_text()
                visible_forbidden = [
                    phrase
                    for phrase in (
                        "机构核验状态",
                        "证据来源与校验",
                        "摘要证据定位",
                        "支持文本哈希",
                        "事实边界",
                        "标识与类别",
                        "source_verified",
                        "enrichment provenance",
                        "中文综述总结",
                        "All rights reserved.",
                        "IOP Publishing Ltd",
                        "Published by Elsevier",
                        "Creative Commons:",
                        "open access article under the CC BY",
                    )
                    if phrase in visible_detail_text
                ]
                if visible_forbidden:
                    researcher_contract_leaks.append(
                        {
                            "href": str(candidate_href),
                            "kind": "visible-forbidden-copy",
                            "values": visible_forbidden,
                        }
                    )
                overflow_audit = page.evaluate(
                    """
                    () => {
                      const root = document.documentElement;
                      const offenders = [...document.querySelectorAll(
                        '.evidence-hero, .evidence-panel, .evidence-relation-card, '
                        + '.evidence-abstract, .evidence-translation, .evidence-synthesis'
                      )].filter(node => node.scrollWidth > node.clientWidth + 1).map(node => ({
                        className: node.className || '',
                        clientWidth: node.clientWidth,
                        scrollWidth: node.scrollWidth,
                        text: (node.innerText || '').trim().slice(0, 120)
                      }));
                      return {
                        documentClientWidth: root.clientWidth,
                        documentScrollWidth: root.scrollWidth,
                        pageOverflow: root.scrollWidth > root.clientWidth + 1,
                        offenders
                      };
                    }
                    """
                )
                if overflow_audit["pageOverflow"] or overflow_audit["offenders"]:
                    layout_failures.append(
                        {"href": str(candidate_href), **overflow_audit}
                    )
                evidence_snapshot: dict[str, object] = {
                    name: _browser_semantic_items(
                        page.locator(
                            f'[data-acceptance-content="{name}"] '
                            '[data-evidence-present="true"]'
                        )
                    )
                    for name in (
                        "external-original",
                        "local-original",
                        "abstract-evidence",
                        "core-conclusions",
                    )
                }
                evidence_snapshot["abstract-translation-zh"] = (
                    _browser_semantic_items(
                        page.locator(
                            '[data-acceptance-content="abstract-evidence"] '
                            ".evidence-translation p"
                        )
                    )
                )
                evidence_snapshot["synthesis-zh"] = _browser_semantic_items(
                    page.locator(
                        '[data-acceptance-content="core-conclusions"] '
                        ".evidence-synthesis p"
                    )
                )
                evidence_snapshot["archive-relations"] = page.locator(
                    '[data-acceptance-content="archive-relations"] '
                    '[data-evidence-present="true"]'
                ).evaluate_all(
                    """
                    nodes => nodes.map(node => {
                      const style = getComputedStyle(node);
                      const rect = node.getBoundingClientRect();
                      const body = node.querySelector('.evidence-relation-body');
                      const groups = body ? [...body.querySelectorAll(':scope > div')] : [...node.querySelectorAll(':scope > div')];
                      const link = node.querySelector('.evidence-source-jump[href]') || node.querySelector('header h3 a[href]') || node.querySelector('a[href]');
                      return {
                        visible: !node.hidden && node.getAttribute('aria-hidden') !== 'true'
                          && style.display !== 'none' && style.visibility !== 'hidden'
                          && rect.width > 0 && rect.height > 0,
                        text: (node.innerText || node.textContent || '').trim(),
                        href: link ? (link.getAttribute('href') || '') : '',
                        research_title: node.querySelector('.evidence-relation-topic')?.innerText.trim() || '',
                        document_title: node.querySelector('header h3')?.innerText.trim() || '',
                        relation_label: groups[0]?.querySelector('strong')?.innerText.trim() || '',
                        usage_description: groups[1]?.querySelector('p')?.innerText.trim() || '',
                        source_excerpt: node.querySelector(':scope > blockquote')?.innerText.trim() || '',
                        source_location: node.querySelector('.evidence-source-jump')?.innerText.trim() || ''
                      };
                    })
                    """
                )
                section_expectations: dict[str, bool | None] = {}
                for name in (
                    "external-original",
                    "local-original",
                    "abstract-evidence",
                    "core-conclusions",
                    "archive-relations",
                ):
                    section = page.locator(
                        f'[data-acceptance-content="{name}"]'
                    )
                    status = (
                        section.get_attribute("data-evidence-status")
                        if section.count() == 1
                        else None
                    )
                    section_expectations[name] = (
                        True
                        if status == "present"
                        else False
                        if status == "missing"
                        else None
                    )
                browser_status_counts["abstract-translation-zh"] += int(
                    len(evidence_snapshot["abstract-translation-zh"]) > 0
                )
                browser_status_counts["synthesis-zh"] += int(
                    len(evidence_snapshot["synthesis-zh"]) > 0
                )
                for name, expected in section_expectations.items():
                    if expected is True:
                        browser_status_counts[name] += 1

                paper_id = str(candidate_href).rstrip("/").rsplit("/", 1)[-1]
                detail_api_response = context.request.get(
                    base + f"/api/v1/evidence/papers/{paper_id}"
                )
                detail_api_payload = (
                    detail_api_response.json()
                    if detail_api_response.status == 200
                    else {}
                )
                detail_api_data = (
                    detail_api_payload.get("data", {})
                    if isinstance(detail_api_payload, dict)
                    else {}
                )
                leaked_api_keys = _researcher_api_internal_keys(detail_api_data)
                if leaked_api_keys:
                    researcher_contract_leaks.append(
                        {
                            "href": str(candidate_href),
                            "kind": "public-api-internal-keys",
                            "values": leaked_api_keys,
                        }
                    )
                relation_contract_leaks = [
                    {
                        "document_title": relation.get("document_title"),
                        "href": relation.get("href"),
                    }
                    for relation in evidence_snapshot["archive-relations"]
                    if relation.get("document_title") == "研究概览"
                    or "/documents/" not in str(relation.get("href") or "")
                ]
                if relation_contract_leaks:
                    researcher_contract_leaks.append(
                        {
                            "href": str(candidate_href),
                            "kind": "generic-or-landing-relation",
                            "values": relation_contract_leaks,
                        }
                    )
                api_coverage = detail_api_data.get("evidence_coverage", {})
                api_expectations: dict[str, bool | None] = {
                    "external-original": api_coverage.get("external_original"),
                    "local-original": api_coverage.get("local_original"),
                    "abstract-evidence": api_coverage.get("abstract_evidence"),
                    "core-conclusions": api_coverage.get("core_conclusions"),
                    "archive-relations": api_coverage.get("archive_relations"),
                    "abstract-translation-zh": bool(
                        detail_api_data.get("chinese_presentation")
                    ),
                    "synthesis-zh": bool(
                        detail_api_data.get("chinese_presentation")
                    ),
                }
                status_mismatches = [
                    name
                    for name in (
                        "external-original",
                        "local-original",
                        "abstract-evidence",
                        "core-conclusions",
                        "archive-relations",
                    )
                    if section_expectations.get(name) is not api_expectations.get(name)
                ]
                for name, expected in api_expectations.items():
                    if expected is True:
                        api_content_counts[name] += 1
                semantic_passed, semantic_evidence = (
                    _validate_evidence_detail_snapshot(
                        evidence_snapshot, api_expectations
                    )
                )
                failed_sections = [
                    name
                    for name, result in semantic_evidence["checks"].items()
                    if result.get("passed") is not True
                ]
                if (
                    detail_api_response.status != 200
                    or status_mismatches
                    or failed_sections
                ):
                    semantic_failures.append(
                        {
                            "href": str(candidate_href),
                            "api_status": detail_api_response.status,
                            "status_mismatches": status_mismatches,
                            "failed_sections": failed_sections,
                            "checks": {
                                name: semantic_evidence["checks"][name]
                                for name in failed_sections
                            },
                        }
                    )
                for name, expected in api_expectations.items():
                    if expected is True:
                        semantic_coverage[name]["expected"] += 1
                        if semantic_evidence["checks"][name]["passed"] is True:
                            semantic_coverage[name]["valid"] += 1
                if (
                    semantic_passed
                    and not status_mismatches
                    and all(value is True for value in api_expectations.values())
                    and complete_evidence_href is None
                ):
                    complete_evidence_href = str(candidate_href)
                    complete_evidence_snapshot = evidence_snapshot
                    complete_evidence_validation = semantic_evidence
            browser_valid_counts = {
                name: counts["valid"]
                for name, counts in semantic_coverage.items()
            }
            database_contract_counts = {
                name: effective_database_content_counts[name]
                for name in _EVIDENCE_CONTENT_CONTRACT
            }
            aggregate_passed, aggregate_evidence = (
                _validate_evidence_aggregate_counts(
                    browser_expected=browser_status_counts,
                    browser_valid=browser_valid_counts,
                    api=api_content_counts,
                    database=database_contract_counts,
                    release=effective_release_content_counts,
                )
            )
            record(
                "evidence-content-counts-browser-api-database-release-exact",
                aggregate_passed,
                aggregate_evidence,
            )
            record(
                "evidence-all-details-semantic-content",
                len(evidence_detail_hrefs) == evidence_count
                and not semantic_failures
                and not layout_failures
                and not researcher_contract_leaks
                and aggregate_passed
                and all(
                    counts["expected"] > 0
                    and counts["valid"] == counts["expected"]
                    for counts in semantic_coverage.values()
                ),
                {
                    "scanned": len(evidence_detail_hrefs),
                    "catalogue": evidence_count,
                    "coverage": semantic_coverage,
                    "failure_count": len(semantic_failures),
                    "failures": semantic_failures[:12],
                    "layout_failure_count": len(layout_failures),
                    "layout_failures": layout_failures[:12],
                    "researcher_contract_leak_count": len(researcher_contract_leaks),
                    "researcher_contract_leaks": researcher_contract_leaks[:12],
                },
            )
            record(
                "evidence-complete-semantic-detail-discovered",
                complete_evidence_href is not None,
                {"href": complete_evidence_href},
            )
            assert complete_evidence_href is not None
            assert complete_evidence_snapshot is not None
            assert complete_evidence_validation is not None
            evidence_detail_href = complete_evidence_href
            page.goto(base + complete_evidence_href, wait_until="networkidle")
            for section_name, section_result in complete_evidence_validation[
                "checks"
            ].items():
                record(
                    f"evidence-content-{section_name}",
                    section_result.get("passed") is True,
                    section_result,
                )

            evidence_detail_probe = context.request.get(
                base + complete_evidence_href
            )
            record(
                "evidence-semantic-paper-detail-http",
                evidence_detail_probe.status == 200,
                {
                    "status": evidence_detail_probe.status,
                    "url": complete_evidence_href,
                    "body_preview": evidence_detail_probe.text()[:500]
                    if evidence_detail_probe.status != 200
                    else "",
                },
            )
            local_resource_href = str(
                complete_evidence_snapshot["local-original"][0]["href"]
            )
            record(
                "evidence-local-resource-link-visible",
                bool(local_resource_href)
                and local_resource_href.startswith(
                    (
                        "/api/v1/evidence/resources/",
                        "/evidence/library/",
                    )
                ),
                local_resource_href or "missing",
            )
            local_resource_response = context.request.get(base + local_resource_href)
            local_resource_bytes = local_resource_response.body()
            local_resource_sha256, local_resource_digest_source = (
                _verified_response_sha256(
                    local_resource_response.headers, local_resource_bytes
                )
            )
            record(
                "evidence-local-resource-download",
                local_resource_response.status == 200
                and local_resource_bytes.startswith(b"%PDF-")
                and bool(local_resource_sha256),
                {
                    "status": local_resource_response.status,
                    "bytes": len(local_resource_bytes),
                    "sha256": local_resource_sha256,
                    "digest_source": local_resource_digest_source,
                },
            )
            page.screenshot(path=str(screenshots / "04-evidence-detail.png"), full_page=True)

            page.goto(base + "/paper-lab/", wait_until="networkidle")
            expect(page.locator("#paper-lab-summary")).to_contain_text("当前显示")
            record(
                "paper-lab-column-contract",
                page.locator("#paper-lab-table th[data-colkey]").count() == 37,
                page.locator("#paper-lab-table th[data-colkey]").count(),
            )
            record(
                "paper-lab-column-groups",
                page.locator("#paper-column-groups fieldset").count() == 8,
                page.locator("#paper-column-groups fieldset").count(),
            )
            paper_rows = page.locator("#paper-lab-rows tr").count()
            record("paper-lab-curated-catalogue", paper_rows == 31, paper_rows)
            first_title_button = page.locator("#paper-lab-rows tr .paper-title-button").first
            first_paper_id = first_title_button.get_attribute("data-open-paper")
            record("paper-lab-title-opens-detail", bool(first_paper_id), first_paper_id or "missing")
            first_title_button.click()
            expect(page.locator("#paper-detail-drawer")).to_have_attribute("aria-hidden", "false")
            record(
                "paper-lab-detail-drawer",
                page.locator("#paper-drawer-content .paper-drawer-field").count() == 30,
                page.locator("#paper-drawer-content .paper-drawer-field").count(),
            )
            page.locator("#paper-drawer-close").click()
            page.locator("#paper-lab-curated-toggle").click()
            expect(page.locator("#paper-lab-summary")).to_contain_text("137 / 137")
            paper_rows = page.locator("#paper-lab-rows tr").count()
            record("paper-lab-full-catalogue", paper_rows == 137, paper_rows)
            record("paper-lab-full-mode-url-state", "mode=all" in page.url, page.url)
            page.locator("#paper-tab-stats").click()
            record("paper-lab-statistics", page.locator("#paper-stats article").count() == 6, page.locator("#paper-stats article").count())
            page.locator("#paper-tab-list").click()
            assert first_paper_id is not None
            first_paper_href = f"/paper-lab/papers/{first_paper_id}"
            page.locator("#paper-lab-query").fill("Transformer")
            page.wait_for_timeout(500)
            record("paper-lab-filter-url-state", "q=Transformer" in page.url, page.url)
            record("paper-lab-filter-result", page.locator("#paper-lab-rows tr").count() > 0, page.locator("#paper-lab-rows tr").count())
            page.screenshot(path=str(screenshots / "05-paper-lab-filter.png"), full_page=True)

            page.goto(base + "/paper-lab/designer", wait_until="networkidle")
            expect(page.locator("#designer-status")).to_contain_text("已加载")
            page.locator("#designer-tab-tags").click()
            expect(page.locator("#designer-tag-summary")).to_contain_text("301 / 301")
            record("designer-tag-catalogue", page.locator("#designer-tag-grid article").count() == 301, page.locator("#designer-tag-grid article").count())
            page.locator("#designer-tab-pipeline").click()
            add_buttons = page.locator(".component-add:not([disabled])")
            record("designer-components", add_buttons.count() > 0, add_buttons.count())
            add_buttons.first.click()
            page.locator("#designer-visualize").click()
            page.locator("#designer-architecture-dialog[open]").wait_for(state="visible")
            record("designer-architecture-svg", page.locator("#designer-architecture-canvas svg").count() == 1, page.locator("#designer-architecture-canvas svg").count())
            page.locator("#designer-architecture-close").click()
            blueprint_name = f"浏览器验收-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
            page.locator("#designer-name").fill(blueprint_name)
            page.locator("#designer-objective").fill("验证积木选择、契约校验、不可变保存与恢复。")
            page.locator("#designer-validate").click()
            expect(page.locator("#designer-status")).to_contain_text("验证通过")
            page.locator("#designer-save").click()
            expect(page.locator("#designer-status")).to_contain_text("已保存第")
            record("designer-save", "已保存第 1 版" in page.locator("#designer-status").inner_text(), page.locator("#designer-status").inner_text())
            page.reload(wait_until="networkidle")
            expect(page.locator("#designer-status")).to_contain_text("已加载")
            page.locator("#designer-blueprint").select_option(label=f"{blueprint_name} · v1")
            page.locator("#designer-load").click()
            expect(page.locator("#designer-status")).to_contain_text("已恢复")
            record("designer-restore", blueprint_name in page.locator("#designer-name").input_value(), page.locator("#designer-status").inner_text())
            page.screenshot(path=str(screenshots / "06-designer-restored.png"), full_page=True)

            page.goto(base + str(first_paper_href), wait_until="networkidle")
            page.locator(".paper-field-editor").evaluate("element => element.open = true")
            summary_field = page.locator('[data-paper-edit-field="summary"]')
            summary_field.locator("textarea").fill("浏览器端到端验收覆盖层")
            summary_field.locator(".paper-edit-reason").fill("自动验收写入隔离数据库副本")
            summary_field.locator(".paper-edit-save").click()
            expect(page.locator("#paper-editor-status")).to_contain_text("已保存为覆盖层")
            record("viewer-versioned-edit", "第 1 版" in page.locator("#paper-editor-status").inner_text(), page.locator("#paper-editor-status").inner_text())

            mobile = context.new_page()
            mobile.set_viewport_size({"width": 390, "height": 844})
            mobile.goto(base + "/", wait_until="networkidle")
            home_widths = mobile.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("mobile-home-no-body-overflow", home_widths["scroll"] <= home_widths["client"] + 1, home_widths)
            mobile.screenshot(path=str(screenshots / "07-home-mobile.png"), full_page=True)
            assert q2_href is not None
            mobile.goto(base + str(q2_href), wait_until="networkidle")
            q2_mobile_widths = mobile.evaluate(
                "({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})"
            )
            q2_mobile_columns = mobile.locator(".q2-pipeline-flow").evaluate(
                "element => getComputedStyle(element).gridTemplateColumns"
            )
            record(
                "mobile-q2-pipeline-no-body-overflow",
                q2_mobile_widths["scroll"] <= q2_mobile_widths["client"] + 1
                and " " not in q2_mobile_columns.strip(),
                {"widths": q2_mobile_widths, "grid_columns": q2_mobile_columns},
            )
            mobile.screenshot(
                path=str(screenshots / "07a-q2-pipeline-mobile.png"),
                full_page=False,
            )
            mobile.goto(base + str(diagram_href or research_href), wait_until="networkidle")
            research_widths = mobile.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("mobile-research-no-body-overflow", research_widths["scroll"] <= research_widths["client"] + 1, research_widths)
            mobile_diagram = mobile.locator(".ascii-diagram[data-ascii-diagram='enhanced']").first
            record("mobile-ascii-svg", mobile_diagram.locator("svg.diagram-svg").count() == 1, mobile_diagram.locator("svg.diagram-svg").count())
            mobile_diagram.locator("details summary").click()
            mobile_raw_widths = mobile.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("mobile-ascii-original-no-body-overflow", mobile_raw_widths["scroll"] <= mobile_raw_widths["client"] + 1, mobile_raw_widths)
            mobile.screenshot(path=str(screenshots / "08-research-mobile.png"), full_page=True)
            mobile.goto(base + str(evidence_detail_href), wait_until="networkidle")
            evidence_widths = mobile.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("mobile-evidence-no-body-overflow", evidence_widths["scroll"] <= evidence_widths["client"] + 1, evidence_widths)
            mobile.screenshot(path=str(screenshots / "09-evidence-mobile.png"), full_page=True)
            mobile.goto(base + "/paper-lab/", wait_until="networkidle")
            expect(mobile.locator("#paper-lab-summary")).to_contain_text("当前显示")
            paper_lab_widths = mobile.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("mobile-paper-lab-no-body-overflow", paper_lab_widths["scroll"] <= paper_lab_widths["client"] + 1, paper_lab_widths)
            mobile.screenshot(path=str(screenshots / "10-paper-lab-mobile.png"), full_page=True)
            mobile.goto(base + "/paper-lab/designer", wait_until="networkidle")
            expect(mobile.locator("#designer-status")).to_contain_text("已加载")
            designer_widths = mobile.evaluate("({scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth})")
            record("mobile-designer-no-body-overflow", designer_widths["scroll"] <= designer_widths["client"] + 1, designer_widths)
            mobile.screenshot(path=str(screenshots / "11-designer-mobile.png"), full_page=True)
            mobile.close()
            context.close()
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=10)

    source_after = _tree(archive)
    proj2_after = _tree(project / "reference" / "proj2")
    delivery_databases_after = {
        name: _file_identity(delivery / "db" / name)
        for name in database_names
    }
    frozen_migrations_after = _tree(frozen_migration_root.parent)
    managed_delivery_after = {
        name: safe_tree(delivery / name)
        for name in managed_delivery_before
    }
    current_source_after = safe_tree(
        current_app_source, exclude_runtime_caches=True
    )
    frozen_source_after = safe_tree(
        frozen_app_source, exclude_runtime_caches=True
    )
    record("archive-source-unchanged", source_before == source_after, {"before": source_before, "after": source_after})
    record("proj2-source-unchanged", proj2_before == proj2_after, {"before": proj2_before, "after": proj2_after})
    record(
        "delivery-databases-unchanged",
        delivery_databases_before == delivery_databases_after,
        {"before": delivery_databases_before, "after": delivery_databases_after},
    )
    record(
        "frozen-migration-contract-unchanged",
        frozen_migrations_before == frozen_migrations_after,
        {"before": frozen_migrations_before, "after": frozen_migrations_after},
    )
    record(
        "delivery-managed-trees-unchanged",
        managed_delivery_before == managed_delivery_after,
        {"before": managed_delivery_before, "after": managed_delivery_after},
    )
    record(
        "browser-app-source-matches-frozen-source",
        current_source_before
        == current_source_after
        == frozen_source_before
        == frozen_source_after,
        {
            "current_before": current_source_before,
            "current_after": current_source_after,
            "frozen_before": frozen_source_before,
            "frozen_after": frozen_source_after,
        },
    )
    relevant_console_errors = [
        message for message in console_errors
        if "favicon" not in message.casefold()
    ]
    record("server-5xx-responses", not server_errors, server_errors)
    record("browser-console-clean", not relevant_console_errors, relevant_console_errors)
    report = {
        "schema_version": "qrh-browser-acceptance/v1",
        "status": "PASS",
        "checked_at": datetime.now(UTC).isoformat(),
        "base_url": base,
        "browser_executable": str(args.browser_executable.resolve(strict=True)),
        "delivery_var": str(delivery),
        "isolated_var": str(var),
        "checks": checks,
        "server_errors": server_errors,
        "console_errors": relevant_console_errors,
        "source_integrity": {"archive": source_after, "proj2": proj2_after},
        "delivery_database_integrity": delivery_databases_after,
        "frozen_migration_contract": frozen_migrations_after,
        "runtime_code": safe_tree(frozen_code_root, exclude_runtime_caches=True),
        "runtime_toolchain": runtime_toolchain(),
        "activation_seal": {
            "path": str(activation_path),
            "sha256": _file_identity(activation_path)["sha256"],
        },
        "screenshots": sorted(path.relative_to(output).as_posix() for path in screenshots.glob("*.png")),
    }
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
