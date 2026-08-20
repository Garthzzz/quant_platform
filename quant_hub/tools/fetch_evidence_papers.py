"""Materialize and acquire Archive Evidence papers in the user-facing papers library.

The script reads a reviewed delivery database without mutating it. Existing verified
PDF resources are copied into ``quant_hub/paper_lab/papers`` with stable readable
names. Missing PDFs are fetched only from public arXiv or bibliographic open-access
locations and every attempt is recorded in a UTF-8 JSON manifest.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DELIVERY = ROOT / "quant_hub" / "var" / "delivery-final-reviewed-v5-20260716-v9"
DEFAULT_OUTPUT = ROOT / "quant_hub" / "paper_lab" / "papers"
USER_AGENT = "QuantResearchHub/1.0 (local research evidence acquisition)"
MAX_PDF_BYTES = 120 * 1024 * 1024


def _json_url(url: str) -> dict[str, Any] | None:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=25) as response:
            payload = response.read(12 * 1024 * 1024)
    except (HTTPError, URLError, TimeoutError, OSError):
        return None
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _safe_component(value: str, *, limit: int) -> str:
    text = re.sub(r"[<>:\"/\\|?*\x00-\x1f]+", "_", value)
    text = re.sub(r"\s+", " ", text).strip(" ._")
    return (text or "paper")[:limit].rstrip(" ._")


def _identifier_label(identifiers: dict[str, str], paper_id: str) -> str:
    if identifiers.get("arxiv"):
        return "arxiv_" + identifiers["arxiv"]
    if identifiers.get("doi"):
        return "doi_" + identifiers["doi"]
    return paper_id


def _target_path(output: Path, title: str, identifiers: dict[str, str], paper_id: str) -> Path:
    prefix = _safe_component(_identifier_label(identifiers, paper_id), limit=72)
    readable = _safe_component(title, limit=105)
    return output / f"{prefix}__{readable}.pdf"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verified_pdf(payload: bytes) -> bool:
    return len(payload) >= 10_000 and payload[:5] == b"%PDF-" and b"%%EOF" in payload[-8192:]


def _download_pdf(url: str) -> tuple[bytes | None, str, str]:
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/pdf,application/octet-stream;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urlopen(request, timeout=40) as response:
            final_url = response.geturl()
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_PDF_BYTES:
                    return None, final_url, "resource_too_large"
                chunks.append(chunk)
    except HTTPError as error:
        return None, url, f"http_{error.code}"
    except (URLError, TimeoutError, OSError) as error:
        return None, url, f"network_{type(error).__name__}"
    payload = b"".join(chunks)
    if not _verified_pdf(payload):
        return None, final_url, "not_verified_pdf"
    return payload, final_url, "verified_pdf"


def _openalex_metadata(doi: str) -> dict[str, Any] | None:
    return _json_url("https://api.openalex.org/works/https://doi.org/" + quote(doi, safe=""))


def _semantic_scholar_metadata(doi: str) -> dict[str, Any] | None:
    fields = "title,authors,externalIds,openAccessPdf,url,publicationDate"
    return _json_url(
        "https://api.semanticscholar.org/graph/v1/paper/DOI:"
        + quote(doi, safe="")
        + "?fields="
        + fields
    )


def _crossref_metadata(doi: str) -> dict[str, Any] | None:
    wrapper = _json_url("https://api.crossref.org/works/" + quote(doi, safe=""))
    if not wrapper or not isinstance(wrapper.get("message"), dict):
        return None
    return wrapper["message"]


def _candidate_urls(
    identifiers: dict[str, str],
    metadata: dict[str, Any],
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    arxiv_id = identifiers.get("arxiv")
    if arxiv_id:
        candidates.append({"url": f"https://arxiv.org/pdf/{arxiv_id}", "source": "arxiv"})
        return candidates

    doi = identifiers.get("doi")
    if not doi:
        return candidates
    openalex = metadata.get("openalex")
    if isinstance(openalex, dict):
        locations: list[Any] = []
        for key in ("best_oa_location", "primary_location"):
            value = openalex.get(key)
            if isinstance(value, dict):
                locations.append(value)
        raw_locations = openalex.get("locations")
        if isinstance(raw_locations, list):
            locations.extend(raw_locations)
        for location in locations:
            if not isinstance(location, dict):
                continue
            url = location.get("pdf_url")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                candidates.append({"url": url, "source": "openalex_oa_location"})
    semantic = metadata.get("semantic_scholar")
    if isinstance(semantic, dict):
        oa = semantic.get("openAccessPdf")
        if isinstance(oa, dict):
            url = oa.get("url")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                candidates.append({"url": url, "source": "semantic_scholar_open_access"})
    crossref = metadata.get("crossref")
    if isinstance(crossref, dict):
        links = crossref.get("link")
        if isinstance(links, list):
            for item in links:
                if not isinstance(item, dict):
                    continue
                url = item.get("URL")
                content_type = str(item.get("content-type", "")).lower()
                if (
                    isinstance(url, str)
                    and url.startswith(("http://", "https://"))
                    and ("pdf" in content_type or url.lower().endswith(".pdf"))
                ):
                    candidates.append({"url": url, "source": "crossref_fulltext_link"})
    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in candidates:
        if item["url"] not in seen:
            unique.append(item)
            seen.add(item["url"])
    return unique


def _paper_rows(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        """
        SELECT catalog.paper_id,catalog.title,catalog.authors_json,
               catalog.institutions_json,catalog.core_conclusions_json,
               catalog.local_resources_json
        FROM paper_catalog_projection AS catalog
        ORDER BY lower(catalog.title),catalog.paper_id
        """
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        identifiers = {
            str(item["scheme"]): str(item["normalized_value"])
            for item in connection.execute(
                """
                SELECT scheme,normalized_value FROM paper_identifier_assertion
                WHERE paper_id=? AND assertion_status='verified'
                ORDER BY scheme
                """,
                (row["paper_id"],),
            ).fetchall()
        }
        resources = connection.execute(
            """
            SELECT resource_id,relative_path,content_sha256,bytes,rights_status
            FROM paper_resource
            WHERE paper_id=? AND verification_status='verified'
            ORDER BY resource_id
            """,
            (row["paper_id"],),
        ).fetchall()
        result.append(
            {
                "paper_id": row["paper_id"],
                "title": row["title"],
                "identifiers": identifiers,
                "authors": json.loads(row["authors_json"]),
                "institutions": json.loads(row["institutions_json"]),
                "conclusions": json.loads(row["core_conclusions_json"]),
                "resources": [dict(item) for item in resources],
            }
        )
    connection.close()
    return result


def run(delivery: Path, output: Path) -> dict[str, Any]:
    database = delivery / "db" / "research_papers.sqlite3"
    if not database.is_file():
        raise FileNotFoundError(database)
    output.mkdir(parents=True, exist_ok=True)
    papers = _paper_rows(database)
    manifest: dict[str, Any] = {
        "schema_version": "qrh-evidence-user-facing-paper-library/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_delivery": str(delivery),
        "source_database": str(database),
        "output_root": str(output),
        "papers": [],
    }
    for index, paper in enumerate(papers, start=1):
        target = _target_path(output, paper["title"], paper["identifiers"], paper["paper_id"])
        item: dict[str, Any] = {
            "paper_id": paper["paper_id"],
            "title": paper["title"],
            "identifiers": paper["identifiers"],
            "target": str(target.relative_to(ROOT)).replace("\\", "/"),
            "status": "missing",
            "source": None,
            "source_url": None,
            "attempts": [],
            "metadata": {},
        }
        copied = False
        for resource in paper["resources"]:
            source = delivery / "research_papers" / resource["relative_path"]
            if not source.is_file():
                item["attempts"].append({"source": "reviewed_delivery", "result": "source_missing", "path": str(source)})
                continue
            payload = source.read_bytes()
            if not _verified_pdf(payload) or _sha256(payload) != resource["content_sha256"]:
                item["attempts"].append({"source": "reviewed_delivery", "result": "source_integrity_failed", "path": str(source)})
                continue
            if not target.exists() or _sha256(target.read_bytes()) != resource["content_sha256"]:
                shutil.copyfile(source, target)
            item.update(
                {
                    "status": "materialized_verified_resource",
                    "source": "reviewed_delivery",
                    "sha256": resource["content_sha256"],
                    "bytes": resource["bytes"],
                }
            )
            copied = True
            break
        if not copied:
            doi = paper["identifiers"].get("doi")
            if doi:
                item["metadata"] = {
                    "openalex": _openalex_metadata(doi),
                    "semantic_scholar": _semantic_scholar_metadata(doi),
                    "crossref": _crossref_metadata(doi),
                }
            for candidate in _candidate_urls(paper["identifiers"], item["metadata"]):
                payload, final_url, result = _download_pdf(candidate["url"])
                item["attempts"].append(
                    {
                        "source": candidate["source"],
                        "requested_url": candidate["url"],
                        "final_url": final_url,
                        "result": result,
                    }
                )
                if payload is None:
                    continue
                target.write_bytes(payload)
                item.update(
                    {
                        "status": "downloaded_verified_pdf",
                        "source": candidate["source"],
                        "source_url": final_url,
                        "sha256": _sha256(payload),
                        "bytes": len(payload),
                    }
                )
                break
                
        manifest["papers"].append(item)
        print(f"[{index:02d}/{len(papers)}] {item['status']}: {paper['title']}", flush=True)
        time.sleep(0.15)
    statuses: dict[str, int] = {}
    for item in manifest["papers"]:
        statuses[item["status"]] = statuses.get(item["status"], 0) + 1
    manifest["summary"] = {
        "canonical_papers": len(papers),
        "pdf_files": sum(1 for item in manifest["papers"] if item["status"] != "missing"),
        "missing": statuses.get("missing", 0),
        "statuses": statuses,
    }
    manifest_path = output / "ACQUISITION_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest["summary"], ensure_ascii=False, sort_keys=True))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--delivery", type=Path, default=DEFAULT_DELIVERY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifest = run(args.delivery.resolve(), args.output.resolve())
    return 0 if manifest["summary"]["pdf_files"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
