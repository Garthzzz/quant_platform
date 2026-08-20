from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import unquote, urlsplit


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CITATION_ID_RE = re.compile(r"^cit_[a-z2-7]{52}$")
_ARXIV_RE = re.compile(
    r"^(?:[a-z.-]+/[0-9]{7}|[0-9]{4}\.[0-9]{4,5})(?:v(?P<version>[0-9]+))?$",
    re.IGNORECASE,
)


def stable_evidence_id(prefix: str, *parts: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]*", prefix):
        raise ValueError("invalid evidence ID prefix")
    digest = hashlib.sha256(b"\0".join(part.encode("utf-8") for part in parts)).hexdigest()
    return f"{prefix}_{digest[:32]}"


def citation_id_for_marker(
    document_sha256: str,
    byte_start: int,
    byte_end: int,
    raw_marker: str | bytes,
) -> str:
    """按 qrh-citation-v1 生成稳定、无截断的公共引用 ID。"""

    if not _SHA256_RE.fullmatch(document_sha256):
        raise ValueError("document_sha256 must be lowercase SHA-256 hex")
    if byte_start < 0 or byte_end <= byte_start:
        raise ValueError("citation byte span must be a non-empty half-open interval")
    marker_bytes = raw_marker.encode("utf-8") if isinstance(raw_marker, str) else raw_marker
    marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    payload = (
        b"qrh-citation-v1\0"
        + document_sha256.encode("ascii")
        + b"\0"
        + str(byte_start).encode("ascii")
        + b"\0"
        + str(byte_end).encode("ascii")
        + b"\0"
        + marker_sha256.encode("ascii")
    )
    encoded = base64.b32encode(hashlib.sha256(payload).digest()).decode("ascii")
    citation_id = "cit_" + encoded.rstrip("=").lower()
    if not _CITATION_ID_RE.fullmatch(citation_id):
        raise RuntimeError("citation ID encoder violated the public contract")
    return citation_id


def citation_id_for_locator(
    document_sha256: str,
    locator_kind: str,
    locator: dict[str, object],
    raw_marker: str | bytes,
) -> str:
    """为无原始 UTF-8 byte span 的 PDF/历史 locator claim 生成独立域 ID。"""

    if not _SHA256_RE.fullmatch(document_sha256):
        raise ValueError("document_sha256 must be lowercase SHA-256 hex")
    if locator_kind not in {"pdf_extracted_page_line", "source_locator_claim"}:
        raise ValueError("non-byte citation locator kind is unsupported")
    marker_bytes = raw_marker.encode("utf-8") if isinstance(raw_marker, str) else raw_marker
    locator_json = json.dumps(
        locator, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    payload = (
        b"qrh-citation-locator-v1\0"
        + document_sha256.encode("ascii")
        + b"\0"
        + locator_kind.encode("ascii")
        + b"\0"
        + hashlib.sha256(locator_json).hexdigest().encode("ascii")
        + b"\0"
        + hashlib.sha256(marker_bytes).hexdigest().encode("ascii")
    )
    encoded = base64.b32encode(hashlib.sha256(payload).digest()).decode("ascii")
    value = "cit_" + encoded.rstrip("=").lower()
    if not _CITATION_ID_RE.fullmatch(value):
        raise RuntimeError("locator citation ID encoder violated the public contract")
    return value


def validate_citation_id(value: str) -> str:
    if not _CITATION_ID_RE.fullmatch(value):
        raise ValueError("citation ID is not canonical")
    return value


def _strip_identifier_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        return value
    host = parsed.netloc.lower().split(":", 1)[0]
    path = unquote(parsed.path).strip("/")
    if host in {"doi.org", "dx.doi.org"}:
        return path
    if host in {"arxiv.org", "www.arxiv.org"}:
        for prefix in ("abs/", "pdf/"):
            if path.lower().startswith(prefix):
                path = path[len(prefix) :]
                break
        return path.removesuffix(".pdf")
    if host in {"pubmed.ncbi.nlm.nih.gov", "www.ncbi.nlm.nih.gov"}:
        return path
    return value


def normalize_identifier(scheme: str, value: str) -> str:
    """规范化强标识符；无法无损识别时拒绝，而不是猜测。"""

    normalized_scheme = scheme.strip().lower()
    raw = _strip_identifier_url(value.strip())
    if normalized_scheme == "doi":
        raw = re.sub(r"^(?:doi\s*:\s*)", "", raw, flags=re.IGNORECASE).strip().lower()
        if not re.fullmatch(r"10\.[0-9]{4,9}/\S+", raw):
            raise ValueError("invalid DOI")
        return raw.rstrip(".,;")
    if normalized_scheme == "arxiv":
        raw = re.sub(r"^arxiv\s*:\s*", "", raw, flags=re.IGNORECASE).strip().lower()
        match = _ARXIV_RE.fullmatch(raw)
        if match is None:
            raise ValueError("invalid arXiv identifier")
        if match.group("version") is not None:
            raw = raw[: raw.lower().rfind("v")]
        return raw
    if normalized_scheme == "pmid":
        raw = re.sub(r"^pmid\s*:\s*", "", raw, flags=re.IGNORECASE).strip().strip("/")
        if not re.fullmatch(r"[1-9][0-9]*", raw):
            raise ValueError("invalid PMID")
        return raw
    if normalized_scheme == "pmcid":
        raw = re.sub(r"^pmcid\s*:\s*", "", raw, flags=re.IGNORECASE).strip().strip("/")
        if not re.fullmatch(r"pmc[1-9][0-9]*", raw, flags=re.IGNORECASE):
            raise ValueError("invalid PMCID")
        return raw.lower()
    if normalized_scheme == "report":
        raw = re.sub(r"\s+", "-", raw.strip()).lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]{2,127}", raw):
            raise ValueError("invalid report identifier")
        return raw
    if normalized_scheme == "url":
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("invalid external URL")
        return value.strip().lower()
    if normalized_scheme == "isbn":
        raw = re.sub(r"[-\s]", "", raw).lower()
        if not re.fullmatch(r"(?:[0-9]{9}[0-9x]|[0-9]{13})", raw):
            raise ValueError("invalid ISBN")
        return raw
    raise ValueError(f"unsupported identifier scheme: {scheme!r}")
