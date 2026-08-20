"""Build a source-bound draft for the Evidence fields rejected by the UI audit."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import html
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any
from urllib.parse import quote

import fitz

from fetch_evidence_papers import _json_url


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DELIVERY = ROOT / "quant_hub" / "var" / "delivery-final-reviewed-v5-20260716-v9"
DEFAULT_LIBRARY = ROOT / "quant_hub" / "paper_lab" / "papers"
DEFAULT_OUTPUT = (
    ROOT
    / "project_state"
    / "workers"
    / "evidence_substantive_enrichment_20260716"
    / "draft_enrichment.json"
)


def _normalized_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _clean_text(value: str) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", value))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _openalex_abstract(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    positions: list[tuple[int, str]] = []
    for token, indexes in value.items():
        if not isinstance(token, str) or not isinstance(indexes, list):
            continue
        for index in indexes:
            if isinstance(index, int) and index >= 0:
                positions.append((index, token))
    if not positions:
        return None
    return _clean_text(" ".join(token for _, token in sorted(positions)))


def _openalex_by_title(title: str) -> dict[str, Any] | None:
    wrapper = _json_url(
        "https://api.openalex.org/works?per-page=5&search=" + quote(title, safe="")
    )
    if not wrapper or not isinstance(wrapper.get("results"), list):
        return None
    expected = _normalized_title(title)
    ranked: list[tuple[float, dict[str, Any]]] = []
    for result in wrapper["results"]:
        if not isinstance(result, dict):
            continue
        candidate = _normalized_title(str(result.get("title") or ""))
        if not candidate:
            continue
        if candidate == expected:
            return result
        common = len(set(candidate) & set(expected)) / max(1, len(set(candidate) | set(expected)))
        ranked.append((common, result))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[0][1] if ranked and ranked[0][0] >= 0.85 else None


def _metadata_institutions(metadata: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    names: list[str] = []
    sources: list[dict[str, str]] = []
    openalex = metadata.get("openalex")
    if isinstance(openalex, dict):
        for authorship in openalex.get("authorships") or []:
            if not isinstance(authorship, dict):
                continue
            for institution in authorship.get("institutions") or []:
                if not isinstance(institution, dict):
                    continue
                name = _clean_text(str(institution.get("display_name") or ""))
                if name and name not in names:
                    names.append(name)
                    sources.append({"source": "openalex_authorship", "value": name})
    crossref = metadata.get("crossref")
    if isinstance(crossref, dict):
        for author in crossref.get("author") or []:
            if not isinstance(author, dict):
                continue
            for affiliation in author.get("affiliation") or []:
                if not isinstance(affiliation, dict):
                    continue
                name = _clean_text(str(affiliation.get("name") or ""))
                if name and name not in names:
                    names.append(name)
                    sources.append({"source": "crossref_author_affiliation", "value": name})
    return names, sources


_INSTITUTION_RE = re.compile(
    r"\b(?:University|Universit[a-zéèä]+|Institute|Institut|College|School|Department|"
    r"Laborator(?:y|ies)|Research Center|Research Centre|Academy|Google|DeepMind|"
    r"Microsoft|IBM|Meta AI|Amazon|Bloomberg|INRIA|CNRS|ETH|EPFL|MIT|Stanford|"
    r"Carnegie Mellon|Princeton|Harvard|Berkeley|Bank of|Federal Reserve)\b",
    re.IGNORECASE,
)


def _pdf_text(path: Path) -> tuple[list[str], list[str]]:
    document = fitz.open(path)
    pages = [page.get_text("text", sort=True) for page in document]
    document.close()
    return pages, [hashlib.sha256(page.encode("utf-8")).hexdigest() for page in pages]


def _pdf_institutions(first_pages: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    names: list[str] = []
    sources: list[dict[str, str]] = []
    for page_number, page in enumerate(first_pages[:2], start=1):
        for raw in page.splitlines():
            line = _clean_text(raw)
            if (
                not 5 <= len(line) <= 180
                or "@" in line
                or line.casefold().startswith(("abstract", "keywords", "copyright"))
                or not _INSTITUTION_RE.search(line)
            ):
                continue
            line = re.sub(r"^[*†‡\d,;\s]+", "", line).strip()
            if line and line not in names:
                names.append(line)
                sources.append(
                    {
                        "source": "paper_pdf_first_pages",
                        "page": str(page_number),
                        "value": line,
                    }
                )
    return names[:12], sources[:12]


_ABSTRACT_HEADING_RE = re.compile(
    r"(?im)^\s*(?:abstract|summary)\s*(?:[.—:-]\s*)?"
)
_ABSTRACT_STOP_RE = re.compile(
    r"(?im)^\s*(?:keywords?|index terms?|jel classification|\d+\.?\s+introduction|i\.?\s+introduction|introduction)\b"
)
_CONCLUSION_HEADING_RE = re.compile(
    r"(?im)^\s*(?:\d+(?:\.\d+)*\.?\s+)?(?:conclusions?|concluding remarks|discussion(?: and conclusions?)?|summary)\s*$"
)
_CONCLUSION_STOP_RE = re.compile(
    r"(?im)^\s*(?:references|bibliography|acknowledg(?:e)?ments?|appendix)\s*$"
)


def _extract_abstract(pages: list[str]) -> tuple[str | None, dict[str, Any] | None]:
    material = "\n".join(pages[:3])
    match = _ABSTRACT_HEADING_RE.search(material)
    if match is None:
        return None, None
    tail = material[match.end() :]
    stop = _ABSTRACT_STOP_RE.search(tail)
    excerpt = tail[: stop.start()] if stop else tail[:6000]
    excerpt = _clean_text(excerpt)
    if not 80 <= len(excerpt) <= 6000:
        return None, None
    return excerpt, {"source_kind": "paper_pdf", "field": "paper.abstract", "pdf_pages": [1, 2, 3]}


def _extract_conclusion(pages: list[str], abstract: str | None) -> tuple[str | None, dict[str, Any] | None]:
    offset = max(0, len(pages) - 8)
    material = "\n".join(pages[offset:])
    matches = list(_CONCLUSION_HEADING_RE.finditer(material))
    if matches:
        match = matches[-1]
        tail = material[match.end() :]
        stop = _CONCLUSION_STOP_RE.search(tail)
        excerpt = _clean_text(tail[: stop.start()] if stop else tail[:5000])
        if len(excerpt) >= 80:
            return excerpt[:5000], {
                "source_kind": "paper_pdf",
                "field": "paper.conclusion_section",
                "section": _clean_text(match.group(0)),
                "pdf_pages": list(range(offset + 1, len(pages) + 1)),
            }
    if abstract:
        return abstract, {
            "source_kind": "paper_pdf_or_bibliographic_abstract",
            "field": "paper.abstract",
            "reason": "no distinct conclusion section was extracted",
        }
    return None, None


def _database_rows(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows: list[dict[str, Any]] = []
    for row in connection.execute(
        """
        SELECT paper_id,title,authors_json,institutions_json,core_conclusions_json
        FROM paper_catalog_projection ORDER BY lower(title),paper_id
        """
    ):
        identifiers = {
            str(item["scheme"]): str(item["normalized_value"])
            for item in connection.execute(
                """
                SELECT scheme,normalized_value FROM paper_identifier_assertion
                WHERE paper_id=? AND assertion_status='verified' ORDER BY scheme
                """,
                (row["paper_id"],),
            )
        }
        excerpts = [
            dict(item)
            for item in connection.execute(
                """
                SELECT excerpt_text,excerpt_sha256,locator_json,provenance_urn
                FROM evidence_excerpt WHERE paper_id=? ORDER BY excerpt_id
                """,
                (row["paper_id"],),
            )
        ]
        rows.append(
            {
                **dict(row),
                "identifiers": identifiers,
                "authors": json.loads(row["authors_json"]),
                "institutions": json.loads(row["institutions_json"]),
                "conclusions": json.loads(row["core_conclusions_json"]),
                "excerpts": excerpts,
            }
        )
    connection.close()
    return rows


def run(delivery: Path, library: Path, output: Path) -> dict[str, Any]:
    manifest = json.loads((library / "ACQUISITION_MANIFEST.json").read_text(encoding="utf-8"))
    acquisitions = {item["paper_id"]: item for item in manifest["papers"]}
    rows = _database_rows(delivery / "db" / "research_papers.sqlite3")
    result: dict[str, Any] = {
        "schema_version": "qrh-substantive-evidence-enrichment-draft/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_delivery": str(delivery),
        "source_acquisition_manifest": str(library / "ACQUISITION_MANIFEST.json"),
        "papers": [],
    }
    for index, row in enumerate(rows, start=1):
        acquisition = acquisitions[row["paper_id"]]
        metadata = acquisition.get("metadata") if isinstance(acquisition.get("metadata"), dict) else {}
        if not metadata.get("openalex"):
            metadata["openalex"] = _openalex_by_title(row["title"])
            time.sleep(0.12)
        institutions = list(row["institutions"])
        institution_sources: list[dict[str, str]] = []
        metadata_names, metadata_sources = _metadata_institutions(metadata)
        for name in metadata_names:
            if name not in institutions:
                institutions.append(name)
        institution_sources.extend(metadata_sources)
        target = ROOT / acquisition["target"]
        pages: list[str] = []
        page_hashes: list[str] = []
        if target.is_file():
            try:
                pages, page_hashes = _pdf_text(target)
            except (RuntimeError, ValueError):
                pages = []
                page_hashes = []
        pdf_names, pdf_sources = _pdf_institutions(pages)
        for name in pdf_names:
            if name not in institutions:
                institutions.append(name)
        institution_sources.extend(pdf_sources)
        abstract_text: str | None = None
        abstract_source: dict[str, Any] | None = None
        if not row["excerpts"]:
            abstract_text, abstract_source = _extract_abstract(pages)
            if abstract_text is None:
                crossref = metadata.get("crossref")
                if isinstance(crossref, dict) and crossref.get("abstract"):
                    abstract_text = _clean_text(str(crossref["abstract"]))
                    abstract_source = {
                        "source_kind": "crossref",
                        "field": "crossref.message.abstract",
                        "source_url": "https://api.crossref.org/works/" + row["identifiers"].get("doi", ""),
                    }
            if abstract_text is None:
                openalex = metadata.get("openalex")
                if isinstance(openalex, dict):
                    abstract_text = _openalex_abstract(openalex.get("abstract_inverted_index"))
                    if abstract_text:
                        abstract_source = {
                            "source_kind": "openalex",
                            "field": "openalex.abstract_inverted_index",
                            "source_url": str(openalex.get("id") or ""),
                        }
        conclusion_text: str | None = None
        conclusion_source: dict[str, Any] | None = None
        if not row["conclusions"]:
            conclusion_text, conclusion_source = _extract_conclusion(pages, abstract_text)
        item = {
            "paper_id": row["paper_id"],
            "title": row["title"],
            "identifiers": row["identifiers"],
            "authors": row["authors"],
            "institutions": institutions,
            "institution_source": {
                "records": institution_sources,
                "source_policy": "existing_verified_metadata_then_openalex_crossref_then_pdf_first_pages",
            },
            "existing_abstract": bool(row["excerpts"]),
            "existing_conclusion": bool(row["conclusions"]),
            "abstract_text": abstract_text,
            "abstract_sha256": hashlib.sha256(abstract_text.encode("utf-8")).hexdigest() if abstract_text else None,
            "abstract_source": abstract_source,
            "core_conclusion_text": conclusion_text,
            "core_conclusion_source": conclusion_source,
            "local_pdf_relative_path": acquisition["target"] if target.is_file() else None,
            "local_pdf_sha256": acquisition.get("sha256") if target.is_file() else None,
            "local_pdf_bytes": acquisition.get("bytes") if target.is_file() else None,
            "local_pdf_source_url": acquisition.get("source_url") if target.is_file() else None,
            "pdf_page_count": len(pages),
            "pdf_page_sha256": page_hashes,
            "acquisition_status": acquisition["status"],
            "review_status": "needs_chinese_review" if abstract_text else "source_gap",
        }
        result["papers"].append(item)
        print(
            f"[{index:02d}/{len(rows)}] inst={len(institutions)} abstract={bool(row['excerpts'] or abstract_text)} "
            f"conclusion={bool(row['conclusions'] or conclusion_text)} pdf={target.is_file()} {row['title']}",
            flush=True,
        )
    result["summary"] = {
        "papers": len(result["papers"]),
        "with_institutions": sum(bool(item["institutions"]) for item in result["papers"]),
        "with_abstract": sum(bool(item["existing_abstract"] or item["abstract_text"]) for item in result["papers"]),
        "with_conclusion": sum(bool(item["existing_conclusion"] or item["core_conclusion_text"]) for item in result["papers"]),
        "with_local_pdf": sum(bool(item["local_pdf_relative_path"]) for item in result["papers"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], ensure_ascii=False, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delivery", type=Path, default=DEFAULT_DELIVERY)
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = run(args.delivery.resolve(), args.library.resolve(), args.output.resolve())
    return 0 if result["summary"]["papers"] == 78 else 1


if __name__ == "__main__":
    raise SystemExit(main())
