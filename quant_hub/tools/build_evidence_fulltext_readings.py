"""生成或复核 18 篇 Evidence PDF 的确定性全文读取结果。"""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from quant_hub.platform.workflow import canonical_json


SCHEMA_VERSION = "qrh-evidence-fulltext-reading/v1"
ALGORITHM_VERSION = "pymupdf-text-pages-and-source-bounded-claims/v1"


class _MetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, list[str]] = {}

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.casefold() != "meta":
            return
        attributes = {key.casefold(): value for key, value in attrs}
        name = attributes.get("name")
        value = attributes.get("content")
        if name and value is not None:
            self.values.setdefault(name, []).append(value)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", value.casefold()))


def _normalized_text(value: str) -> str:
    return " ".join(value.replace("\r\n", "\n").replace("\r", "\n").split())


def _rows(workspace: Path) -> list[dict[str, Any]]:
    try:
        import fitz  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("全文读取 gate 需要 PyMuPDF（fitz）") from error

    formal = workspace / "quant_hub"
    package = workspace / "project_state" / "workers" / "e_evidence_bulk_data"
    manifest_path = formal / "fixtures" / "evidence" / "normalized_resource_manifest.jsonl"
    manifest = [
        json.loads(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    results: list[dict[str, Any]] = []
    heading_re = re.compile(
        r"^(?:[0-9]+(?:\.[0-9]+)*\s+)?"
        r"(?:conclusions?|concluding remarks|discussion(?: and conclusions?)?|summary)\s*$",
        re.IGNORECASE,
    )
    for resource in sorted(manifest, key=lambda item: str(item["candidate_id"])):
        candidate_id = str(resource["candidate_id"])
        arxiv_id = str(resource["arxiv_id_claim"])
        pdf_path = package.joinpath(*Path(resource["artifact"]["local_path"]).parts)
        pdf_bytes = pdf_path.read_bytes()
        if _sha256(pdf_bytes) != resource["payload"]["sha256"]:
            raise RuntimeError(f"PDF hash 漂移：{candidate_id}")
        abs_relative = str(resource["official_abstract_page"]["local_path"])
        abs_bytes = package.joinpath(*Path(abs_relative).parts).read_bytes()
        if _sha256(abs_bytes) != resource["official_abstract_page"]["body_sha256"]:
            raise RuntimeError(f"官方摘要页 hash 漂移：{candidate_id}")
        parser = _MetaParser()
        parser.feed(abs_bytes.decode("utf-8"))
        abstracts = parser.values.get("citation_abstract") or []
        titles = parser.values.get("citation_title") or []
        identifiers = parser.values.get("citation_arxiv_id") or []
        if len(abstracts) != 1 or len(titles) != 1 or identifiers != [arxiv_id]:
            raise RuntimeError(f"官方摘要元数据不完整：{candidate_id}")

        document = fitz.open(stream=pdf_bytes, filetype="pdf")
        pages: list[str] = []
        page_records: list[dict[str, object]] = []
        headings: list[dict[str, object]] = []
        for page_number, page in enumerate(document, start=1):
            page_text = page.get_text("text", sort=True).replace("\r\n", "\n").replace(
                "\r", "\n"
            )
            pages.append(page_text)
            page_records.append(
                {
                    "page": page_number,
                    "characters": len(page_text),
                    "text_sha256": _sha256(page_text.encode("utf-8")),
                }
            )
            for line in page_text.splitlines():
                normalized_line = _normalized_text(line)
                if heading_re.fullmatch(normalized_line):
                    headings.append({"page": page_number, "text": normalized_line})
        document.close()
        full_text = "\f".join(pages)
        if not pages or any(not page.strip() for page in pages):
            raise RuntimeError(f"全文读取产生空页：{candidate_id}")
        front_text = " ".join(pages[: min(3, len(pages))])
        title_tokens = _tokens(titles[0])
        front_tokens = _tokens(front_text)
        title_coverage = len(title_tokens & front_tokens) / max(1, len(title_tokens))
        abstract_tokens = _tokens(abstracts[0])
        full_tokens = _tokens(full_text)
        abstract_coverage = len(abstract_tokens & full_tokens) / max(1, len(abstract_tokens))
        if title_coverage < 0.8 or abstract_coverage < 0.7:
            raise RuntimeError(
                f"全文与官方元数据覆盖不足：{candidate_id} "
                f"title={title_coverage:.3f} abstract={abstract_coverage:.3f}"
            )

        source_provenance = (
            f"qrh:evidence:arxiv-abs:{arxiv_id}:"
            f"sha256:{resource['official_abstract_page']['body_sha256']}"
        )
        analysis_payload: dict[str, object] = {
            "analysis": {
                "reading_mode": "full_pdf_text_extraction_and_source_bounded_understanding",
                "algorithm_version": ALGORITHM_VERSION,
                "reader_engine": "PyMuPDF",
                "reader_engine_version": str(fitz.VersionBind),
                "fulltext": {
                    "page_count": len(pages),
                    "nonempty_page_count": sum(bool(page.strip()) for page in pages),
                    "characters": len(full_text),
                    "text_sha256": _sha256(full_text.encode("utf-8")),
                    "pages": page_records,
                },
                "document_identity_checks": {
                    "arxiv_id": arxiv_id,
                    "official_title": titles[0],
                    "title_token_coverage_first_three_pages": round(title_coverage, 6),
                    "official_abstract_token_coverage_fulltext": round(
                        abstract_coverage, 6
                    ),
                },
                "detected_conclusion_headings": headings,
                "semantic_scope": (
                    "PDF 每页均已读取并形成逐页 hash；当前可发布语义仅采用官方摘要"
                    "逐字 source_claim，不把自动抽取等同于人工全文结论审核。"
                ),
            },
            "core_conclusions": [
                {
                    "text": abstracts[0],
                    "fact_status": "source_claim",
                    "claim_scope": "official_abstract_verbatim",
                    "verification_status": "source_verified_not_human_fulltext_reviewed",
                    "provenance_urn": source_provenance,
                }
            ],
            "fact_boundary": {
                "fulltext_bytes": "verified_pdf_source",
                "fulltext_text": "deterministic_extraction",
                "core_conclusions": "official_abstract_source_claim",
                "model_inference": "none",
                "human_fulltext_review": "not_completed",
            },
        }
        material = {
            "schema_version": SCHEMA_VERSION,
            "source_candidate_id": candidate_id,
            "arxiv_id": arxiv_id,
            "pdf_sha256": str(resource["payload"]["sha256"]),
            "pdf_bytes": int(resource["payload"]["bytes"]),
            "abstract_page_sha256": str(
                resource["official_abstract_page"]["body_sha256"]
            ),
            "analysis_payload": analysis_payload,
        }
        material_hash = _sha256(canonical_json(material).encode("utf-8"))
        results.append(
            {
                **material,
                "reading_material_sha256": material_hash,
                "provenance_urn": (
                    f"qrh:evidence:fulltext-reading:{candidate_id}:sha256:{material_hash}"
                ),
                "result_status": "succeeded",
            }
        )
    if len(results) != 18:
        raise RuntimeError("全文读取结果必须严格覆盖 18 篇论文")
    return results


def _payload(workspace: Path) -> bytes:
    return ("\n".join(canonical_json(row) for row in _rows(workspace)) + "\n").encode(
        "utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    workspace = Path.cwd().resolve(strict=True)
    target = arguments.output or (
        workspace
        / "quant_hub"
        / "fixtures"
        / "evidence"
        / "fulltext_reading_results.jsonl"
    )
    payload = _payload(workspace)
    if arguments.verify:
        if target.read_bytes() != payload:
            raise RuntimeError("冻结全文读取结果与当前 PDF/算法重放不一致")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".fulltext-reading-", dir=target.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "status": "PASS",
                "rows": 18,
                "output": str(target),
                "sha256": _sha256(payload),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
