from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import json
import re
from typing import Any


OVERLAY_SCHEMA = "qrh-evidence-chinese-presentation/v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidencePresentationError(RuntimeError):
    pass


def _required_text(item: dict[str, object], field: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise EvidencePresentationError(f"中文 Evidence 展示层字段无效：{field}")
    return value.strip()


@lru_cache(maxsize=1)
def chinese_overlays_by_excerpt() -> dict[str, dict[str, Any]]:
    """按官方摘要文本哈希读取只读中文辅助展示层。

    译文和综述从不进入 Evidence 事实表；只有与当前 ``evidence_excerpt``
    的逐字摘要哈希完全一致时，查询层才会展示它们。
    """

    resource = files("quant_hub.presentation").joinpath("evidence_zh_overlays.json")
    if not resource.is_file():
        return {}
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidencePresentationError("中文 Evidence 展示层无法安全读取") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != OVERLAY_SCHEMA:
        raise EvidencePresentationError("中文 Evidence 展示层 schema 不受支持")
    entries = payload.get("entries")
    excluded = payload.get("excluded")
    if not isinstance(entries, list) or not isinstance(excluded, list):
        raise EvidencePresentationError("中文 Evidence 展示层清单结构无效")

    result: dict[str, dict[str, Any]] = {}
    identifiers: set[tuple[str, str]] = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise EvidencePresentationError("中文 Evidence 展示条目必须是对象")
        digest = _required_text(raw, "source_excerpt_sha256")
        if not _SHA256_RE.fullmatch(digest) or digest in result:
            raise EvidencePresentationError("中文 Evidence 展示条目摘要哈希无效或重复")
        try:
            source_bytes = int(raw.get("source_excerpt_bytes", -1))
        except (TypeError, ValueError) as error:
            raise EvidencePresentationError("中文 Evidence 展示条目摘要字节数无效") from error
        if source_bytes <= 0:
            raise EvidencePresentationError("中文 Evidence 展示条目摘要字节数无效")
        scheme = _required_text(raw, "identifier_scheme").casefold()
        identifier = _required_text(raw, "normalized_identifier")
        identity = (scheme, identifier)
        if identity in identifiers:
            raise EvidencePresentationError("中文 Evidence 展示条目强标识符重复")
        identifiers.add(identity)
        if raw.get("translation_status") != "generated_reference_translation":
            raise EvidencePresentationError("中文参考译文事实边界无效")
        if raw.get("summary_status") != "generated_research_aid_not_source_fact":
            raise EvidencePresentationError("中文综述事实边界无效")
        fact_boundary = raw.get("fact_boundary")
        if not isinstance(fact_boundary, str) or not fact_boundary.strip():
            raise EvidencePresentationError("中文 Evidence 展示条目缺少事实边界")
        result[digest] = {
            "identifier_scheme": scheme,
            "normalized_identifier": identifier,
            "title": _required_text(raw, "title"),
            "source_excerpt_sha256": digest,
            "source_excerpt_bytes": source_bytes,
            "source_path": _required_text(raw, "source_path"),
            "abstract_translation_zh": _required_text(
                raw, "abstract_translation_zh"
            ),
            "synthesis_zh": _required_text(raw, "synthesis_zh"),
            "translation_status": str(raw["translation_status"]),
            "summary_status": str(raw["summary_status"]),
            "fact_boundary": fact_boundary.strip(),
        }
    return result


__all__ = [
    "EvidencePresentationError",
    "OVERLAY_SCHEMA",
    "chinese_overlays_by_excerpt",
]
