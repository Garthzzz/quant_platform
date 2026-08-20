from __future__ import annotations

from collections import defaultdict
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from quant_hub.runtime_seal import canonical_json, payload_sha256


OVERLAY_SCHEMA = "qrh-evidence-chinese-presentation/v1"
OVERLAY_RELATIVE_PATH = "presentation/evidence_zh_overlays.json"
GENERATED_FACT_BOUNDARY = (
    "官方英文摘要为来源事实；中文译文与综述为生成辅助，不属于来源事实。"
    "不替代全文阅读，也不得扩张原摘要事实边界。"
)
CROSSREF_GENERATED_FACT_BOUNDARY = (
    "Crossref 中出版方提交的英文摘要为来源主张；中文译文与综述为生成辅助，"
    "不属于来源事实。不替代全文阅读，也不得扩张原摘要事实边界。"
)
CROSSREF_ABSTRACT_SOURCE_PREFIX = (
    "project_state/workers/crossref_identity_review/direct_doi_cache/"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CHINESE_RE = re.compile(r"[\u3400-\u9fff]")
_TOP_LEVEL_KEYS = {"schema_version", "generated_at", "entries", "excluded"}
_ENTRY_KEYS = {
    "identifier_scheme",
    "normalized_identifier",
    "title",
    "source_excerpt_sha256",
    "source_excerpt_bytes",
    "source_path",
    "abstract_translation_zh",
    "synthesis_zh",
    "translation_status",
    "summary_status",
    "fact_boundary",
}


class ChineseOverlayContractError(RuntimeError):
    pass


def _required_text(item: dict[str, Any], field: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ChineseOverlayContractError(f"中文展示层字段无效：{field}")
    return value.strip()


def _read_overlay(path: Path) -> tuple[dict[str, Any], dict[str, object]]:
    try:
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
    except FileNotFoundError as error:
        raise ChineseOverlayContractError("正式中文展示层文件不存在") from error
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ChineseOverlayContractError("正式中文展示层在读取期间发生变化")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ChineseOverlayContractError("正式中文展示层不是有效 UTF-8 JSON") from error
    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_KEYS:
        raise ChineseOverlayContractError("正式中文展示层顶层结构无效")
    if payload.get("schema_version") != OVERLAY_SCHEMA:
        raise ChineseOverlayContractError("正式中文展示层 schema 无效")
    if not isinstance(payload.get("generated_at"), str) or not payload["generated_at"].strip():
        raise ChineseOverlayContractError("正式中文展示层缺少生成时间")
    if payload.get("excluded") != []:
        raise ChineseOverlayContractError("正式中文展示层不得排除当前官方摘要")
    if not isinstance(payload.get("entries"), list):
        raise ChineseOverlayContractError("正式中文展示层 entries 无效")
    return payload, {
        "relative_path": OVERLAY_RELATIVE_PATH,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _database_inventory(database: Path) -> tuple[list[dict[str, object]], dict[str, set[tuple[str, str]]]]:
    uri = f"file:{database.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        identifiers: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for row in connection.execute(
            "SELECT paper_id,scheme,normalized_value "
            "FROM identifier_assignment_projection"
        ):
            identifiers[str(row["paper_id"])].add(
                (str(row["scheme"]).casefold(), str(row["normalized_value"]))
            )
        rows = connection.execute(
            """
            SELECT excerpt.paper_id,excerpt.excerpt_text,excerpt.excerpt_sha256,
                   excerpt.locator_json,catalog.title
            FROM evidence_excerpt AS excerpt
            JOIN paper_catalog_projection AS catalog USING(paper_id)
            ORDER BY excerpt.excerpt_sha256
            """
        ).fetchall()

    inventory: list[dict[str, object]] = []
    for row in rows:
        text = str(row["excerpt_text"])
        stored_hash = str(row["excerpt_sha256"])
        actual_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if stored_hash != actual_hash:
            raise ChineseOverlayContractError("官方摘要正文与登记哈希不一致")
        try:
            locator = json.loads(str(row["locator_json"]))
        except json.JSONDecodeError as error:
            raise ChineseOverlayContractError("官方摘要 locator JSON 无效") from error
        source_path = None
        if isinstance(locator, dict):
            source_path = (
                locator.get("source_path")
                or locator.get("cache_path")
                or locator.get("artifact_path")
            )
        if not isinstance(source_path, str) or not source_path:
            raise ChineseOverlayContractError("官方摘要缺少可绑定的来源路径")
        paper_id = str(row["paper_id"])
        inventory.append(
            {
                "paper_id": paper_id,
                "title": str(row["title"]),
                "source_excerpt_sha256": stored_hash,
                "source_excerpt_bytes": len(text.encode("utf-8")),
                "source_path": source_path,
            }
        )
    return inventory, identifiers


def build_chinese_overlay_contract(database: Path, overlay_path: Path) -> dict[str, object]:
    """把正式中文辅助展示层逐条绑定到当前 Evidence 官方摘要快照。"""

    payload, descriptor = _read_overlay(overlay_path)
    inventory, identifiers = _database_inventory(database)
    by_hash = {str(item["source_excerpt_sha256"]): item for item in inventory}
    if len(by_hash) != len(inventory):
        raise ChineseOverlayContractError("官方摘要哈希不是一一映射")

    seen_hashes: set[str] = set()
    seen_identities: set[tuple[str, str]] = set()
    bindings: list[dict[str, object]] = []
    for raw in payload["entries"]:
        if not isinstance(raw, dict) or set(raw) != _ENTRY_KEYS:
            raise ChineseOverlayContractError("正式中文展示条目结构无效")
        digest = _required_text(raw, "source_excerpt_sha256")
        if not _SHA256_RE.fullmatch(digest) or digest in seen_hashes:
            raise ChineseOverlayContractError("正式中文展示条目摘要哈希无效或重复")
        seen_hashes.add(digest)
        try:
            source_bytes = int(raw.get("source_excerpt_bytes", -1))
        except (TypeError, ValueError) as error:
            raise ChineseOverlayContractError("正式中文展示条目摘要字节数无效") from error
        if isinstance(raw.get("source_excerpt_bytes"), bool) or source_bytes <= 0:
            raise ChineseOverlayContractError("正式中文展示条目摘要字节数无效")
        scheme = _required_text(raw, "identifier_scheme").casefold()
        identifier = _required_text(raw, "normalized_identifier")
        identity = (scheme, identifier)
        if identity in seen_identities:
            raise ChineseOverlayContractError("正式中文展示条目强标识符重复")
        seen_identities.add(identity)
        translation = _required_text(raw, "abstract_translation_zh")
        synthesis = _required_text(raw, "synthesis_zh")
        if not _CHINESE_RE.search(translation) or not _CHINESE_RE.search(synthesis):
            raise ChineseOverlayContractError("正式中文展示条目缺少中文译文或综述")
        if raw.get("translation_status") != "generated_reference_translation":
            raise ChineseOverlayContractError("中文参考译文事实边界无效")
        if raw.get("summary_status") != "generated_research_aid_not_source_fact":
            raise ChineseOverlayContractError("中文综述事实边界无效")
        source = by_hash.get(digest)
        if source is None:
            raise ChineseOverlayContractError("正式中文展示条目未绑定当前官方摘要")
        paper_id = str(source["paper_id"])
        if identity not in identifiers.get(paper_id, set()):
            raise ChineseOverlayContractError("正式中文展示条目论文强标识符不一致")
        if _required_text(raw, "title") != source["title"]:
            raise ChineseOverlayContractError("正式中文展示条目论文标题不一致")
        if source_bytes != source["source_excerpt_bytes"]:
            raise ChineseOverlayContractError("正式中文展示条目摘要字节数不一致")
        if _required_text(raw, "source_path") != source["source_path"]:
            raise ChineseOverlayContractError("正式中文展示条目摘要来源路径不一致")
        expected_fact_boundary = (
            CROSSREF_GENERATED_FACT_BOUNDARY
            if scheme == "doi"
            and str(source["source_path"]).startswith(
                CROSSREF_ABSTRACT_SOURCE_PREFIX
            )
            else GENERATED_FACT_BOUNDARY
        )
        if _required_text(raw, "fact_boundary") != expected_fact_boundary:
            raise ChineseOverlayContractError("中文展示条目事实边界与审核契约不一致")
        bindings.append(
            {
                "paper_id": paper_id,
                "identifier_scheme": scheme,
                "normalized_identifier": identifier,
                "source_excerpt_sha256": digest,
                "source_excerpt_bytes": source_bytes,
                "source_path": source["source_path"],
            }
        )

    if seen_hashes != set(by_hash):
        raise ChineseOverlayContractError("正式中文展示层没有完整覆盖当前官方摘要")
    bindings.sort(key=lambda item: str(item["source_excerpt_sha256"]))
    return {
        "schema_version": OVERLAY_SCHEMA,
        "descriptor": descriptor,
        "payload_sha256": payload_sha256(payload),
        "entries": len(payload["entries"]),
        "excluded": 0,
        "database_official_abstracts": len(inventory),
        "bindings_sha256": payload_sha256(bindings),
    }


def build_reviewed_arxiv_official_abstract_projection_contract(
    database: Path,
) -> dict[str, object]:
    """从静止候选重建 reviewed arXiv 29 条官方摘要投影。"""

    uri = f"file:{database.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT receipt.source_candidate_id,
                   receipt.paper_source_candidate_id,
                   identifier.normalized_value,
                   catalog.title,
                   excerpt.excerpt_text,
                   excerpt.excerpt_sha256,
                   excerpt.locator_json
            FROM evidence_canonicalization_receipt AS receipt
            JOIN identifier_assignment_projection AS identifier
              ON identifier.paper_id=receipt.paper_id
             AND identifier.scheme='arxiv'
            JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
            JOIN paper_catalog_projection AS catalog ON catalog.paper_id=receipt.paper_id
            WHERE json_extract(excerpt.locator_json, '$.source_kind')
                  ='official_arxiv_atom_summary'
            ORDER BY receipt.source_candidate_id COLLATE BINARY
            """
        ).fetchall()

    projection: list[dict[str, object]] = []
    source_candidates: set[str] = set()
    identifiers: set[str] = set()
    source_paths: set[str] = set()
    for row in rows:
        source_candidate_id = str(row["source_candidate_id"])
        normalized_identifier = str(row["normalized_value"])
        title = str(row["title"])
        text = str(row["excerpt_text"])
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != str(row["excerpt_sha256"]):
            raise ChineseOverlayContractError("reviewed arXiv 摘要正文哈希不一致")
        try:
            locator = json.loads(str(row["locator_json"]))
        except json.JSONDecodeError as error:
            raise ChineseOverlayContractError("reviewed arXiv 摘要 locator 无效") from error
        if not isinstance(locator, dict):
            raise ChineseOverlayContractError("reviewed arXiv 摘要 locator 无效")
        source_path = str(locator.get("source_path") or "")
        source_file_sha256 = str(locator.get("source_file_sha256") or "")
        try:
            excerpt_bytes = int(locator.get("normalized_excerpt_bytes") or -1)
            source_file_bytes = int(locator.get("source_file_bytes") or -1)
        except (TypeError, ValueError) as error:
            raise ChineseOverlayContractError(
                "reviewed arXiv 摘要 locator 字节数无效"
            ) from error
        if (
            locator.get("source_kind") != "official_arxiv_atom_summary"
            or str(locator.get("normalized_identifier") or "")
            != normalized_identifier
            or str(locator.get("title") or "") != title
            or str(locator.get("normalized_excerpt_sha256") or "") != digest
            or excerpt_bytes != len(text.encode("utf-8"))
            or not source_path.startswith("project_state/")
            or not _SHA256_RE.fullmatch(source_file_sha256)
            or source_file_bytes <= 0
            or not isinstance(locator.get("normalization_contract"), str)
            or not str(locator["normalization_contract"]).strip()
        ):
            raise ChineseOverlayContractError(
                "reviewed arXiv 摘要 locator 与候选投影不一致"
            )
        if (
            not source_candidate_id
            or source_candidate_id in source_candidates
            or normalized_identifier in identifiers
            or source_path in source_paths
        ):
            raise ChineseOverlayContractError(
                "reviewed arXiv 摘要投影缺失或存在重复身份"
            )
        source_candidates.add(source_candidate_id)
        identifiers.add(normalized_identifier)
        source_paths.add(source_path)
        projection.append(
            {
                "source_candidate_id": source_candidate_id,
                "paper_source_candidate_id": str(
                    row["paper_source_candidate_id"]
                ),
                "normalized_identifier": normalized_identifier,
                "title": title,
                "excerpt_sha256": digest,
                "excerpt_bytes": excerpt_bytes,
                "source_path": source_path,
                "source_file_sha256": source_file_sha256,
                "source_file_bytes": source_file_bytes,
            }
        )
    rendered = canonical_json(projection).encode("utf-8")
    return {
        "rows": len(projection),
        "projection_sha256": hashlib.sha256(rendered).hexdigest(),
        "source_candidate_ids_sha256": payload_sha256(
            sorted(source_candidates)
        ),
    }


def build_reviewed_crossref_official_abstract_projection_contract(
    database: Path,
) -> dict[str, object]:
    """从静止候选重建 publisher-deposited Crossref 官方摘要投影。"""

    uri = f"file:{database.resolve(strict=True).as_posix()}?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT receipt.source_candidate_id,
                   receipt.paper_source_candidate_id,
                   identifier.normalized_value,
                   catalog.title,
                   excerpt.excerpt_text,
                   excerpt.excerpt_sha256,
                   excerpt.locator_json
            FROM evidence_canonicalization_receipt AS receipt
            JOIN identifier_assignment_projection AS identifier
              ON identifier.paper_id=receipt.paper_id
             AND identifier.scheme='doi'
            JOIN evidence_excerpt AS excerpt ON excerpt.paper_id=receipt.paper_id
            JOIN paper_catalog_projection AS catalog ON catalog.paper_id=receipt.paper_id
            WHERE json_extract(excerpt.locator_json, '$.source_kind')
                  ='official_crossref_deposit_abstract'
            ORDER BY receipt.source_candidate_id COLLATE BINARY
            """
        ).fetchall()

    projection: list[dict[str, object]] = []
    source_candidates: set[str] = set()
    identifiers: set[str] = set()
    source_paths: set[str] = set()
    for row in rows:
        source_candidate_id = str(row["source_candidate_id"])
        normalized_identifier = str(row["normalized_value"])
        title = str(row["title"])
        text = str(row["excerpt_text"])
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest != str(row["excerpt_sha256"]):
            raise ChineseOverlayContractError("reviewed Crossref 摘要正文哈希不一致")
        try:
            locator = json.loads(str(row["locator_json"]))
        except json.JSONDecodeError as error:
            raise ChineseOverlayContractError(
                "reviewed Crossref 摘要 locator 无效"
            ) from error
        if not isinstance(locator, dict):
            raise ChineseOverlayContractError("reviewed Crossref 摘要 locator 无效")
        source_path = str(locator.get("source_path") or "")
        source_file_sha256 = str(locator.get("source_file_sha256") or "")
        try:
            excerpt_bytes = int(locator.get("normalized_excerpt_bytes") or -1)
            source_file_bytes = int(locator.get("source_file_bytes") or -1)
        except (TypeError, ValueError) as error:
            raise ChineseOverlayContractError(
                "reviewed Crossref 摘要 locator 字节数无效"
            ) from error
        if (
            locator.get("source_kind") != "official_crossref_deposit_abstract"
            or locator.get("field") != "crossref.message.abstract"
            or locator.get("identifier_scheme") != "doi"
            or str(locator.get("normalized_identifier") or "")
            != normalized_identifier
            or str(locator.get("title") or "") != title
            or str(locator.get("normalized_excerpt_sha256") or "") != digest
            or excerpt_bytes != len(text.encode("utf-8"))
            or not source_path.startswith("project_state/")
            or not _SHA256_RE.fullmatch(source_file_sha256)
            or source_file_bytes <= 0
            or not isinstance(locator.get("normalization_contract"), str)
            or not str(locator["normalization_contract"]).strip()
            or locator.get("fact_boundary")
            != "publisher_deposited_source_claim_not_fulltext_review"
        ):
            raise ChineseOverlayContractError(
                "reviewed Crossref 摘要 locator 与候选投影不一致"
            )
        if (
            not source_candidate_id
            or source_candidate_id in source_candidates
            or normalized_identifier in identifiers
            or source_path in source_paths
        ):
            raise ChineseOverlayContractError(
                "reviewed Crossref 摘要投影缺失或存在重复身份"
            )
        source_candidates.add(source_candidate_id)
        identifiers.add(normalized_identifier)
        source_paths.add(source_path)
        projection.append(
            {
                "source_candidate_id": source_candidate_id,
                "paper_source_candidate_id": str(row["paper_source_candidate_id"]),
                "normalized_identifier": normalized_identifier,
                "title": title,
                "excerpt_sha256": digest,
                "excerpt_bytes": excerpt_bytes,
                "source_path": source_path,
                "source_file_sha256": source_file_sha256,
                "source_file_bytes": source_file_bytes,
            }
        )
    rendered = canonical_json(projection).encode("utf-8")
    return {
        "rows": len(projection),
        "projection_sha256": hashlib.sha256(rendered).hexdigest(),
        "source_candidate_ids_sha256": payload_sha256(sorted(source_candidates)),
    }


__all__ = [
    "ChineseOverlayContractError",
    "CROSSREF_GENERATED_FACT_BOUNDARY",
    "GENERATED_FACT_BOUNDARY",
    "OVERLAY_RELATIVE_PATH",
    "OVERLAY_SCHEMA",
    "build_chinese_overlay_contract",
    "build_reviewed_arxiv_official_abstract_projection_contract",
    "build_reviewed_crossref_official_abstract_projection_contract",
]
