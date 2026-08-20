"""Q2/Q5 semantic-chapter browser performance and correctness gate.

The gate is intentionally an external, read-only observer.  It discovers the
active, hash-sealed chapter set from the repository manifest, reconciles that
set with the candidate's public API, and then visits every reconciled route in
real Chromium.  A page is ready only when the product dispatches
``research:ready``; ``DOMContentLoaded`` or a successful HTTP response is not a
substitute for that product milestone.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import time
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright


SCHEMA_VERSION = "qrh-chapter-browser-performance-gate/v1"
TARGET_RESEARCH_SLUGS = (
    "q2-low-snr-neural-selection-factory",
    "q5-factor-history-sequence-compression",
)
# ``visualizes`` documents are byte-sealed source material for an interactive
# landing-page projection.  Their direct routes intentionally redirect to that
# projection, so they are not public chapter pages and must not be sampled as
# if they exposed the chapter-reader DOM contract.
NON_PUBLIC_DOCUMENT_RELATIONSHIPS = frozenset({"visualizes"})
DEFAULT_VIEWPORTS = {
    "desktop": {"width": 1920, "height": 1080},
    "narrow": {"width": 390, "height": 844},
}
DEFAULT_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
DEFAULT_EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

_BLOCK_MATH_RE = re.compile(r"(?<!\\)\$\$(.{1,8000}?)(?<!\\)\$\$", re.DOTALL)
_INLINE_MATH_RE = re.compile(
    r"(?<![\\$])\$(?!\$)([^\n$]{1,2000}?)(?<![\\\s])\$(?!\$)"
)
_RAW_TEX_COMMAND_RE = re.compile(
    r"\\(?:begin|end|frac|dfrac|tfrac|sum|prod|int|left|right|hat|bar|"
    r"mathbf|mathrm|mathbb|mathcal|operatorname|Omega|omega|alpha|beta|"
    r"gamma|delta|theta|lambda|sigma|mu|rho|partial|nabla)\b"
)


class GateContractError(RuntimeError):
    """The candidate or manifest violates the gate's input contract."""


@dataclass(frozen=True)
class ExpectedChapter:
    research_slug: str
    release_key: str
    document_key: str
    document_title: str
    source_path: str
    source_sha256: str
    chapter_key: str
    chapter_revision_id: str
    chapter_title: str
    ordinal: int


@dataclass(frozen=True)
class BrowserTarget:
    research_slug: str
    research_id: str
    release_key: str
    document_key: str
    document_id: str
    document_title: str
    source_path: str
    source_sha256: str
    chapter_key: str
    chapter_revision_id: str
    chapter_title: str
    ordinal: int
    route: str


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = path.read_bytes()
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateContractError(f"invalid UTF-8 JSON: {path}: {error}") from error
    if not isinstance(value, dict):
        raise GateContractError(f"JSON root is not an object: {path}")
    return value, payload


def _require_string(source: Mapping[str, Any], key: str, context: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GateContractError(f"{context}.{key} must be a non-empty string")
    return value


def load_expected_chapters(
    manifest_root: Path,
    *,
    research_slugs: Sequence[str] = TARGET_RESEARCH_SLUGS,
    expected_count: int | None = 58,
) -> tuple[list[ExpectedChapter], dict[str, Any]]:
    """Load and independently verify the active immutable manifest generation."""

    root = manifest_root.resolve()
    active_path = root / "active.json"
    active, active_bytes = _read_json(active_path)
    generation_directory = _require_string(
        active, "generation_directory", "active"
    )
    if not re.fullmatch(r"g-[0-9a-f]{16}", generation_directory):
        raise GateContractError("active.generation_directory is not a safe generation name")
    generation_root = (root / "generations" / generation_directory).resolve()
    if generation_root.parent.parent != root or not generation_root.is_dir():
        raise GateContractError("active generation escapes or is missing from manifest root")

    advertised_files = active.get("files")
    if not isinstance(advertised_files, dict) or not advertised_files:
        raise GateContractError("active.files must be a non-empty hash map")
    file_identities: dict[str, str] = {}
    for relative_name, advertised_hash in sorted(advertised_files.items()):
        if not isinstance(relative_name, str) or Path(relative_name).name != relative_name:
            raise GateContractError(f"unsafe generated manifest filename: {relative_name!r}")
        if not isinstance(advertised_hash, str) or re.fullmatch(
            r"[0-9a-f]{64}", advertised_hash
        ) is None:
            raise GateContractError(f"invalid generated manifest hash: {relative_name}")
        path = generation_root / relative_name
        actual_hash = _sha256_bytes(path.read_bytes())
        if actual_hash != advertised_hash:
            raise GateContractError(
                f"generated manifest hash mismatch: {relative_name}: "
                f"{actual_hash} != {advertised_hash}"
            )
        file_identities[relative_name] = actual_hash

    index, index_bytes = _read_json(generation_root / "index.json")
    advertised_index_hash = _require_string(active, "index_sha256", "active")
    if _sha256_bytes(index_bytes) != advertised_index_hash:
        raise GateContractError("active.index_sha256 does not bind generated index.json")
    research_entries = index.get("research")
    if not isinstance(research_entries, list):
        raise GateContractError("index.research must be a list")

    requested = set(research_slugs)
    found: set[str] = set()
    expected: list[ExpectedChapter] = []
    seen_revision_ids: set[str] = set()
    seen_keys: set[tuple[str, str]] = set()
    manifest_identities: dict[str, str] = {}
    counts_by_research: Counter[str] = Counter()
    manifest_counts_by_research: Counter[str] = Counter()
    excluded_counts_by_research: Counter[str] = Counter()
    for raw_entry in research_entries:
        if not isinstance(raw_entry, dict):
            raise GateContractError("index.research item must be an object")
        research_slug = _require_string(raw_entry, "research_slug", "index.research")
        if research_slug not in requested:
            continue
        if research_slug in found:
            raise GateContractError(f"duplicate research in index: {research_slug}")
        found.add(research_slug)
        manifest_name = _require_string(raw_entry, "manifest_path", research_slug)
        if Path(manifest_name).name != manifest_name:
            raise GateContractError(f"unsafe manifest path for {research_slug}")
        manifest, manifest_bytes = _read_json(generation_root / manifest_name)
        manifest_hash = _sha256_bytes(manifest_bytes)
        if manifest_hash != file_identities.get(manifest_name):
            raise GateContractError(f"manifest is not bound by active pointer: {manifest_name}")
        if _require_string(manifest, "research_slug", manifest_name) != research_slug:
            raise GateContractError(f"research slug mismatch in {manifest_name}")
        manifest_identities[research_slug] = manifest_hash
        binding = manifest.get("archive_release_binding")
        if not isinstance(binding, dict):
            raise GateContractError(f"missing archive release binding: {manifest_name}")
        release_key = _require_string(binding, "archive_release_key", manifest_name)
        documents = manifest.get("documents")
        if not isinstance(documents, list) or not documents:
            raise GateContractError(f"manifest has no documents: {manifest_name}")
        for raw_document in documents:
            if not isinstance(raw_document, dict):
                raise GateContractError(f"invalid document in {manifest_name}")
            document_key = _require_string(raw_document, "document_key", manifest_name)
            document_title = _require_string(raw_document, "display_title", document_key)
            source_path = _require_string(raw_document, "source_path", document_key)
            source_sha256 = _require_string(raw_document, "source_sha256", document_key)
            is_public_document = (
                raw_document.get("relationship")
                not in NON_PUBLIC_DOCUMENT_RELATIONSHIPS
            )
            chapters = raw_document.get("chapters")
            if not isinstance(chapters, list) or not chapters:
                raise GateContractError(f"document has no chapters: {document_key}")
            ordinals: list[int] = []
            for raw_chapter in chapters:
                if not isinstance(raw_chapter, dict):
                    raise GateContractError(f"invalid chapter in {document_key}")
                ordinal = raw_chapter.get("ordinal")
                if not isinstance(ordinal, int) or ordinal < 1:
                    raise GateContractError(f"invalid chapter ordinal in {document_key}")
                chapter_key = _require_string(raw_chapter, "chapter_key", document_key)
                revision_id = _require_string(
                    raw_chapter, "chapter_revision_id", chapter_key
                )
                chapter_title = _require_string(
                    raw_chapter, "display_title", chapter_key
                )
                route_identity = (research_slug, chapter_key)
                if route_identity in seen_keys:
                    raise GateContractError(f"duplicate chapter key: {route_identity}")
                if revision_id in seen_revision_ids:
                    raise GateContractError(f"duplicate chapter revision: {revision_id}")
                seen_keys.add(route_identity)
                seen_revision_ids.add(revision_id)
                ordinals.append(ordinal)
                manifest_counts_by_research[research_slug] += 1
                if is_public_document:
                    counts_by_research[research_slug] += 1
                    expected.append(
                        ExpectedChapter(
                            research_slug=research_slug,
                            release_key=release_key,
                            document_key=document_key,
                            document_title=document_title,
                            source_path=source_path,
                            source_sha256=source_sha256,
                            chapter_key=chapter_key,
                            chapter_revision_id=revision_id,
                            chapter_title=chapter_title,
                            ordinal=ordinal,
                        )
                    )
                else:
                    excluded_counts_by_research[research_slug] += 1
            if ordinals != list(range(1, len(ordinals) + 1)):
                raise GateContractError(
                    f"chapter ordinals are not contiguous for {research_slug}/{document_key}"
                )

    missing = sorted(requested - found)
    if missing:
        raise GateContractError(f"active manifest index is missing research: {missing}")
    expected.sort(
        key=lambda item: (
            research_slugs.index(item.research_slug),
            item.document_key,
            item.ordinal,
        )
    )
    if expected_count is not None and len(expected) != expected_count:
        raise GateContractError(
            f"active target count is {len(expected)}, expected exactly {expected_count}"
        )
    identity = {
        "active_sha256": _sha256_bytes(active_bytes),
        "generation_id": _require_string(active, "generation_id", "active"),
        "generation_directory": generation_directory,
        "index_sha256": advertised_index_hash,
        "manifest_sha256_by_research": manifest_identities,
        "chapter_count": len(expected),
        "chapter_count_by_research": dict(sorted(counts_by_research.items())),
        "manifest_chapter_count": sum(manifest_counts_by_research.values()),
        "manifest_chapter_count_by_research": dict(
            sorted(manifest_counts_by_research.items())
        ),
        "excluded_non_public_chapter_count": sum(
            excluded_counts_by_research.values()
        ),
        "excluded_non_public_chapter_count_by_research": dict(
            sorted(excluded_counts_by_research.items())
        ),
    }
    return expected, identity


def _http_get_json(url: str, timeout_seconds: float) -> tuple[dict[str, Any], dict[str, Any]]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "QuantResearchHub-ChapterPerformanceGate/1",
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = response.read()
            status = int(response.status)
            headers = {key.casefold(): value for key, value in response.headers.items()}
            final_url = response.url
    except HTTPError as error:
        payload = error.read()
        raise GateContractError(
            f"HTTP {error.code} from {url}: {payload[:400]!r}"
        ) from error
    except URLError as error:
        raise GateContractError(f"cannot reach {url}: {error}") from error
    if status != 200:
        raise GateContractError(f"HTTP {status} from {url}")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateContractError(f"invalid JSON from {url}: {error}") from error
    if not isinstance(value, dict):
        raise GateContractError(f"JSON root from {url} is not an object")
    data = value.get("data")
    semantic_payload = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return value, {
        "url": final_url,
        "sha256": _sha256_bytes(payload),
        # API envelopes intentionally contain a per-request request_id.  The
        # semantic digest binds the stable public data while the raw digest is
        # retained for low-level diagnostics.
        "data_sha256": _sha256_bytes(semantic_payload),
        "bytes": len(payload),
        "etag": headers.get("etag"),
    }


def _response_data(payload: Mapping[str, Any], endpoint: str) -> Mapping[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise GateContractError(f"{endpoint} has no object data envelope")
    return data


def reconcile_api_targets(
    expected: Sequence[ExpectedChapter],
    research_rows: Sequence[Mapping[str, Any]],
    detail_by_research_id: Mapping[str, Mapping[str, Any]],
) -> list[BrowserTarget]:
    """Prove the public route set is exactly the active manifest set."""

    expected_slugs = {item.research_slug for item in expected}
    rows_by_slug: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in research_rows:
        if isinstance(row, Mapping):
            slug = row.get("canonical_slug")
            if isinstance(slug, str) and slug in expected_slugs:
                rows_by_slug[slug].append(row)
    for slug in sorted(expected_slugs):
        if len(rows_by_slug[slug]) != 1:
            raise GateContractError(
                f"public API must expose exactly one research row for {slug}; "
                f"got {len(rows_by_slug[slug])}"
            )

    expected_by_identity = {
        (item.research_slug, item.document_key, item.chapter_revision_id): item
        for item in expected
    }
    actual_by_identity: dict[tuple[str, str, str], BrowserTarget] = {}
    for slug, rows in sorted(rows_by_slug.items()):
        row = rows[0]
        research_id = _require_string(row, "research_id", slug)
        detail = detail_by_research_id.get(research_id)
        if not isinstance(detail, Mapping):
            raise GateContractError(f"missing research detail for {slug}/{research_id}")
        if _require_string(detail, "canonical_slug", research_id) != slug:
            raise GateContractError(f"detail research slug mismatch: {research_id}")
        release_key = _require_string(detail, "release_key", research_id)
        documents = detail.get("documents")
        if not isinstance(documents, list):
            raise GateContractError(f"research detail has no documents: {slug}")
        for raw_document in documents:
            if not isinstance(raw_document, Mapping):
                raise GateContractError(f"invalid API document in {slug}")
            if (
                raw_document.get("relationship")
                in NON_PUBLIC_DOCUMENT_RELATIONSHIPS
            ):
                continue
            document_key = raw_document.get("document_key")
            chapters = raw_document.get("chapters")
            if not isinstance(document_key, str) or not isinstance(chapters, list):
                continue
            document_id = _require_string(raw_document, "document_id", document_key)
            document_title = _require_string(
                raw_document, "display_title", document_key
            )
            source_path = _require_string(raw_document, "source_path", document_key)
            source_sha256 = _require_string(
                raw_document, "content_sha256", document_key
            )
            for raw_chapter in chapters:
                if not isinstance(raw_chapter, Mapping):
                    raise GateContractError(f"invalid API chapter in {document_key}")
                revision_id = _require_string(
                    raw_chapter, "chapter_revision_id", document_key
                )
                identity = (slug, document_key, revision_id)
                if identity not in expected_by_identity:
                    raise GateContractError(f"API exposes chapter outside manifest: {identity}")
                if identity in actual_by_identity:
                    raise GateContractError(f"API exposes duplicate chapter route: {identity}")
                expected_item = expected_by_identity[identity]
                chapter_key = _require_string(raw_chapter, "chapter_key", revision_id)
                title = _require_string(raw_chapter, "display_title", revision_id)
                route = _require_string(raw_chapter, "page_url", revision_id)
                ordinal = raw_chapter.get("ordinal")
                if (
                    chapter_key != expected_item.chapter_key
                    or title != expected_item.chapter_title
                    or ordinal != expected_item.ordinal
                    or release_key != expected_item.release_key
                    or document_title != expected_item.document_title
                    or source_path != expected_item.source_path
                    or source_sha256 != expected_item.source_sha256
                ):
                    raise GateContractError(
                        f"API chapter metadata differs from manifest: {identity}"
                    )
                expected_prefix = (
                    f"/research/{research_id}/documents/{document_id}/chapters/"
                )
                if not route.startswith(expected_prefix) or urlparse(route).query:
                    raise GateContractError(f"unsafe or non-canonical chapter route: {route}")
                actual_by_identity[identity] = BrowserTarget(
                    research_slug=slug,
                    research_id=research_id,
                    release_key=release_key,
                    document_key=document_key,
                    document_id=document_id,
                    document_title=document_title,
                    source_path=source_path,
                    source_sha256=source_sha256,
                    chapter_key=chapter_key,
                    chapter_revision_id=revision_id,
                    chapter_title=title,
                    ordinal=int(ordinal),
                    route=route,
                )

    missing = sorted(set(expected_by_identity) - set(actual_by_identity))
    extra = sorted(set(actual_by_identity) - set(expected_by_identity))
    if missing or extra:
        raise GateContractError(
            f"API/manifest chapter coverage mismatch: missing={missing[:5]}, extra={extra[:5]}"
        )
    return [
        actual_by_identity[
            (item.research_slug, item.document_key, item.chapter_revision_id)
        ]
        for item in expected
    ]


def discover_targets(
    base_url: str,
    expected: Sequence[ExpectedChapter],
    *,
    timeout_seconds: float,
) -> tuple[list[BrowserTarget], dict[str, Any]]:
    list_url = urljoin(base_url.rstrip("/") + "/", "api/v1/research")
    list_payload, list_identity = _http_get_json(list_url, timeout_seconds)
    list_data = _response_data(list_payload, list_url)
    research_rows = list_data.get("research")
    if not isinstance(research_rows, list):
        raise GateContractError("research list API has no research array")
    expected_slugs = {item.research_slug for item in expected}
    selected_rows = [
        row
        for row in research_rows
        if isinstance(row, Mapping) and row.get("canonical_slug") in expected_slugs
    ]
    details: dict[str, Mapping[str, Any]] = {}
    detail_identities: dict[str, Any] = {}
    for row in selected_rows:
        research_id = _require_string(row, "research_id", "research-list")
        detail_url = urljoin(
            base_url.rstrip("/") + "/", f"api/v1/research/{research_id}"
        )
        detail_payload, detail_identity = _http_get_json(detail_url, timeout_seconds)
        detail_data = _response_data(detail_payload, detail_url)
        detail = detail_data.get("research")
        if not isinstance(detail, Mapping):
            raise GateContractError(f"research detail has no research object: {research_id}")
        details[research_id] = detail
        detail_identities[research_id] = detail_identity
    targets = reconcile_api_targets(expected, research_rows, details)
    return targets, {
        "research_list": list_identity,
        "research_details": detail_identities,
        "target_count": len(targets),
        "route_set_sha256": _sha256_bytes(
            json.dumps(
                [asdict(item) for item in targets],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ),
    }


def find_residual_math(text: str) -> dict[str, Any]:
    """Find visible TeX that escaped the Markdown/MathML rendering boundary."""

    block_matches = list(_BLOCK_MATH_RE.finditer(text))
    without_blocks = list(text)
    for match in block_matches:
        without_blocks[match.start() : match.end()] = " " * (match.end() - match.start())
    inline_matches = list(_INLINE_MATH_RE.finditer("".join(without_blocks)))
    without_paired_math = without_blocks[:]
    for match in inline_matches:
        without_paired_math[match.start() : match.end()] = " " * (
            match.end() - match.start()
        )
    unpaired_dollars = list(re.finditer(r"(?<!\\)\$", "".join(without_paired_math)))
    command_matches = list(_RAW_TEX_COMMAND_RE.finditer("".join(without_blocks)))

    def snippets(matches: Iterable[re.Match[str]]) -> list[str]:
        values: list[str] = []
        for match in matches:
            value = re.sub(r"\s+", " ", match.group(0)).strip()
            values.append(value[:240])
            if len(values) == 20:
                break
        return values

    return {
        "block_delimiter_count": len(block_matches),
        "inline_delimiter_count": len(inline_matches),
        "unpaired_dollar_count": len(unpaired_dollars),
        "raw_tex_command_count": len(command_matches),
        "block_snippets": snippets(block_matches),
        "inline_snippets": snippets(inline_matches),
        "unpaired_dollar_snippets": snippets(unpaired_dollars),
        "raw_tex_command_snippets": snippets(command_matches),
    }


_READY_INIT_SCRIPT = r"""
(() => {
  const state = {eventAt: null, capturedAt: null, count: 0, detail: null};
  Object.defineProperty(globalThis, "__qrhChapterGateReady", {
    value: state,
    configurable: false,
    enumerable: false,
    writable: false
  });
  globalThis.addEventListener("research:ready", event => {
    state.count += 1;
    if (state.eventAt === null) {
      const advertised = Number(event?.detail?.at);
      state.eventAt = Number.isFinite(advertised) ? advertised : performance.now();
      state.capturedAt = performance.now();
      state.detail = event?.detail ?? null;
    }
  }, {capture: true});
})();
"""


_PAGE_PROBE_SCRIPT = r"""
expected => {
  const nav = performance.getEntriesByType("navigation")[0];
  const resources = performance.getEntriesByType("resource");
  const ready = globalThis.__qrhChapterGateReady || {};
  const body = document.querySelector(".research-body");
  const walkerText = [];
  if (body) {
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (!parent || parent.closest(
        "math,code,pre,script,style,textarea,[data-math-rendered]"
      )) continue;
      const value = node.nodeValue || "";
      if (value.trim()) walkerText.push(value);
    }
  }

  const viewportWidth = document.documentElement.clientWidth;
  const viewportHeight = document.documentElement.clientHeight;
  const rootScrollWidth = Math.max(
    document.documentElement.scrollWidth,
    document.body?.scrollWidth || 0
  );
  const localScrollContainer = element => {
    let cursor = element;
    while (cursor && cursor !== document.body) {
      const style = getComputedStyle(cursor);
      const rect = cursor.getBoundingClientRect();
      if ((style.overflowX === "auto" || style.overflowX === "scroll")
          && cursor.scrollWidth > cursor.clientWidth + 1
          && rect.left >= -1 && rect.right <= viewportWidth + 1) return true;
      cursor = cursor.parentElement;
    }
    return false;
  };
  const unsafe = [];
  for (const element of document.querySelectorAll("body *")) {
    const rect = element.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) continue;
    const crossesViewport = rect.right > viewportWidth + 1 || rect.left < -1;
    if (!crossesViewport || localScrollContainer(element)) continue;
    unsafe.push({
      tag: element.tagName.toLowerCase(),
      id: element.id || null,
      class: String(element.className || "").slice(0, 160),
      left: Math.round(rect.left * 10) / 10,
      right: Math.round(rect.right * 10) / 10,
      width: Math.round(rect.width * 10) / 10,
      scrollWidth: element.scrollWidth,
      clientWidth: element.clientWidth
    });
    if (unsafe.length >= 20) break;
  }

  const currentLinks = [...document.querySelectorAll('a[aria-current="page"]')]
    .map(node => node.getAttribute("href") || "");
  const resourceTransfer = resources.reduce(
    (sum, entry) => sum + (entry.transferSize || 0), 0
  );
  const resourceEncoded = resources.reduce(
    (sum, entry) => sum + (entry.encodedBodySize || 0), 0
  );
  const resourceDecoded = resources.reduce(
    (sum, entry) => sum + (entry.decodedBodySize || 0), 0
  );
  const mathContainers = body
    ? body.querySelectorAll("[data-math-rendered]").length : 0;
  const mathNodes = body ? body.querySelectorAll("math").length : 0;
  const fallbackNodes = body
    ? body.querySelectorAll('[data-math-rendered="fallback"],.math-render-fallback').length
    : 0;

  return {
    navigation: nav ? {
      start_ms: nav.startTime,
      ttfb_ms: nav.responseStart - nav.startTime,
      response_end_ms: nav.responseEnd - nav.startTime,
      dom_interactive_ms: nav.domInteractive - nav.startTime,
      dom_content_loaded_ms: nav.domContentLoadedEventEnd - nav.startTime,
      load_ms: nav.loadEventEnd > 0 ? nav.loadEventEnd - nav.startTime : null,
      transfer_bytes: (nav.transferSize || 0) + resourceTransfer,
      encoded_body_bytes: (nav.encodedBodySize || 0) + resourceEncoded,
      decoded_body_bytes: (nav.decodedBodySize || 0) + resourceDecoded,
      navigation_transfer_bytes: nav.transferSize || 0,
      resource_transfer_bytes: resourceTransfer,
      resource_count: resources.length
    } : null,
    ready: {
      event_at_ms: ready.eventAt,
      captured_at_ms: ready.capturedAt,
      event_count: ready.count || 0,
      dataset_ready: document.documentElement.dataset.researchReady === "true"
    },
    identity: {
      path: location.pathname,
      h1: document.querySelector(".document-page-header h1")?.textContent?.trim() || "",
      context_title: document.querySelector(".document-context-title")?.textContent?.trim() || "",
      article_id: document.querySelector(".research-document")?.id || "",
      current_links: currentLinks,
      title: document.title
    },
    dom: {
      element_count: document.getElementsByTagName("*").length,
      body_element_count: body ? body.getElementsByTagName("*").length : 0,
      body_text_chars: body ? (body.innerText || "").length : 0,
      body_html_chars: body ? body.innerHTML.length : 0,
      document_html_chars: document.documentElement.outerHTML.length,
      research_shell_count: document.querySelectorAll(".research-document-shell").length,
      research_body_count: document.querySelectorAll(".research-body").length
    },
    math: {
      mathml_count: mathNodes,
      rendered_container_count: mathContainers,
      fallback_count: fallbackNodes,
      annotation_xml_count: body ? body.querySelectorAll("annotation-xml").length : 0,
      visible_non_math_text: walkerText.join("\n")
    },
    overflow: {
      viewport_width: viewportWidth,
      viewport_height: viewportHeight,
      root_scroll_width: rootScrollWidth,
      global_horizontal_overflow_px: Math.max(0, rootScrollWidth - viewportWidth),
      unsafe_cross_viewport_count: unsafe.length,
      unsafe_cross_viewport_elements: unsafe
    },
    expected
  };
}
"""


def _sample_checks(
    *,
    target: BrowserTarget,
    status: int | None,
    response_url: str | None,
    redirect_count: int,
    probe: Mapping[str, Any] | None,
    residual_math: Mapping[str, Any],
    console_errors: Sequence[str],
    page_errors: Sequence[str],
    failed_requests: Sequence[str],
    threshold_ms: float,
    load_reached: bool,
) -> dict[str, bool]:
    if not isinstance(probe, Mapping):
        return {
            "http_200": status == 200,
            "canonical_http_response": False,
            "research_ready": False,
            "ready_within_threshold": False,
            "route_identity": False,
            "page_identity": False,
            "dom_contract": False,
            "mathml_contract": False,
            "no_residual_math": False,
            "no_horizontal_overflow": False,
            "load_reached": load_reached,
            "no_browser_errors": False,
        }
    ready = probe.get("ready") if isinstance(probe.get("ready"), Mapping) else {}
    identity = (
        probe.get("identity") if isinstance(probe.get("identity"), Mapping) else {}
    )
    dom = probe.get("dom") if isinstance(probe.get("dom"), Mapping) else {}
    math_data = probe.get("math") if isinstance(probe.get("math"), Mapping) else {}
    overflow = (
        probe.get("overflow") if isinstance(probe.get("overflow"), Mapping) else {}
    )
    ready_ms = ready.get("event_at_ms")
    current_links = identity.get("current_links")
    return {
        "http_200": status == 200,
        "canonical_http_response": (
            redirect_count == 0
            and isinstance(response_url, str)
            and urlparse(response_url).path == target.route
        ),
        "research_ready": (
            isinstance(ready_ms, (int, float))
            and ready.get("dataset_ready") is True
            and ready.get("event_count") == 1
        ),
        "ready_within_threshold": (
            isinstance(ready_ms, (int, float)) and 0 <= ready_ms <= threshold_ms
        ),
        "route_identity": identity.get("path") == target.route,
        "page_identity": (
            identity.get("h1") == target.chapter_title
            and identity.get("context_title") == target.document_title
            and identity.get("article_id") == f"document-{target.document_id}"
            and isinstance(current_links, list)
            and target.route in current_links
        ),
        "dom_contract": (
            dom.get("research_shell_count") == 1
            and dom.get("research_body_count") == 1
            and isinstance(dom.get("body_text_chars"), int)
            and dom.get("body_text_chars", 0) > 0
        ),
        "mathml_contract": (
            math_data.get("fallback_count") == 0
            and math_data.get("annotation_xml_count") == 0
            and math_data.get("mathml_count")
            == math_data.get("rendered_container_count")
        ),
        "no_residual_math": all(
            residual_math.get(key) == 0
            for key in (
                "block_delimiter_count",
                "inline_delimiter_count",
                "unpaired_dollar_count",
                "raw_tex_command_count",
            )
        ),
        "no_horizontal_overflow": (
            isinstance(overflow.get("global_horizontal_overflow_px"), (int, float))
            and overflow.get("global_horizontal_overflow_px", math.inf) <= 1
            and overflow.get("unsafe_cross_viewport_count") == 0
        ),
        "load_reached": load_reached,
        "no_browser_errors": not console_errors and not page_errors and not failed_requests,
    }


def sample_page(
    page: Page,
    *,
    base_url: str,
    target: BrowserTarget,
    viewport_name: str,
    cache_state: str,
    run_number: int,
    threshold_ms: float,
    timeout_ms: int,
) -> dict[str, Any]:
    console_errors: list[str] = []
    page_errors: list[str] = []
    failed_requests: list[str] = []

    def on_console(message: Any) -> None:
        if message.type == "error":
            console_errors.append(message.text)

    def on_page_error(error: Any) -> None:
        page_errors.append(str(error))

    def on_request_failed(request: Any) -> None:
        failure = request.failure
        failed_requests.append(f"{request.method} {request.url}: {failure}")

    page.on("console", on_console)
    page.on("pageerror", on_page_error)
    page.on("requestfailed", on_request_failed)
    url = urljoin(base_url.rstrip("/") + "/", target.route.lstrip("/"))
    status: int | None = None
    response_url: str | None = None
    redirect_count = 0
    load_reached = False
    probe: dict[str, Any] | None = None
    error: str | None = None
    wall_started = time.perf_counter()
    try:
        response = page.goto(url, wait_until="commit", timeout=timeout_ms)
        if response is not None:
            status = response.status
            response_url = response.url
            redirected = response.request.redirected_from
            while redirected is not None:
                redirect_count += 1
                redirected = redirected.redirected_from
        page.wait_for_function(
            "() => globalThis.__qrhChapterGateReady?.eventAt !== null",
            timeout=timeout_ms,
        )
        try:
            page.wait_for_load_state("load", timeout=timeout_ms)
            load_reached = True
        except Exception:
            load_reached = False
        probe = page.evaluate(
            _PAGE_PROBE_SCRIPT,
            {
                "route": target.route,
                "chapter_revision_id": target.chapter_revision_id,
                "document_id": target.document_id,
            },
        )
    except Exception as caught:
        error = f"{type(caught).__name__}: {caught}"
        try:
            probe = page.evaluate(
                _PAGE_PROBE_SCRIPT,
                {
                    "route": target.route,
                    "chapter_revision_id": target.chapter_revision_id,
                    "document_id": target.document_id,
                },
            )
        except Exception:
            probe = None
    finally:
        page.remove_listener("console", on_console)
        page.remove_listener("pageerror", on_page_error)
        page.remove_listener("requestfailed", on_request_failed)

    visible_text = ""
    if isinstance(probe, Mapping):
        math_probe = probe.get("math")
        if isinstance(math_probe, Mapping):
            raw_text = math_probe.get("visible_non_math_text")
            if isinstance(raw_text, str):
                visible_text = raw_text
                # The raw text is only an intermediate scanner input and can be
                # very large; never duplicate research prose into gate reports.
                math_probe = dict(math_probe)
                math_probe.pop("visible_non_math_text", None)
                probe = dict(probe)
                probe["math"] = math_probe
    residual_math = find_residual_math(visible_text)
    checks = _sample_checks(
        target=target,
        status=status,
        response_url=response_url,
        redirect_count=redirect_count,
        probe=probe,
        residual_math=residual_math,
        console_errors=console_errors,
        page_errors=page_errors,
        failed_requests=failed_requests,
        threshold_ms=threshold_ms,
        load_reached=load_reached,
    )
    return {
        "sample_id": (
            f"{viewport_name}:{target.chapter_revision_id}:{cache_state}:{run_number}"
        ),
        "viewport": viewport_name,
        "cache_state": cache_state,
        "run_number": run_number,
        "target": asdict(target),
        "http": {
            "status": status,
            "response_url": response_url,
            "redirect_count": redirect_count,
        },
        "probe": probe,
        "residual_math": residual_math,
        "browser_errors": {
            "console": console_errors,
            "page": page_errors,
            "failed_requests": failed_requests,
        },
        "load_reached": load_reached,
        "host_wall_ms": round((time.perf_counter() - wall_started) * 1000, 3),
        "checks": checks,
        "passed": all(checks.values()) and error is None,
        "error": error,
    }


def _percentile(values: Sequence[float], percentage: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentage
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    weight = position - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


def summarize_samples(
    samples: Sequence[Mapping[str, Any]],
    *,
    targets: Sequence[BrowserTarget],
    viewports: Sequence[str],
    cold_runs: int,
    hot_runs: int,
    threshold_ms: float,
) -> dict[str, Any]:
    expected_per_group = cold_runs + hot_runs
    expected_samples = len(targets) * len(viewports) * expected_per_group
    unique_sample_ids = {
        item.get("sample_id") for item in samples if isinstance(item.get("sample_id"), str)
    }
    route_viewport_counts: Counter[tuple[str, str]] = Counter()
    ready_groups: dict[str, list[float]] = defaultdict(list)
    failed_ids: list[str] = []
    failed_checks: Counter[str] = Counter()
    for sample in samples:
        target = sample.get("target")
        viewport = sample.get("viewport")
        if isinstance(target, Mapping) and isinstance(viewport, str):
            revision_id = target.get("chapter_revision_id")
            if isinstance(revision_id, str):
                route_viewport_counts[(revision_id, viewport)] += 1
        probe = sample.get("probe")
        if isinstance(probe, Mapping):
            ready = probe.get("ready")
            if isinstance(ready, Mapping):
                ready_ms = ready.get("event_at_ms")
                if isinstance(ready_ms, (int, float)):
                    ready_groups[
                        f"{sample.get('viewport')}:{sample.get('cache_state')}"
                    ].append(float(ready_ms))
        if sample.get("passed") is not True:
            failed_ids.append(str(sample.get("sample_id")))
            checks = sample.get("checks")
            if isinstance(checks, Mapping):
                for name, passed in checks.items():
                    if passed is not True:
                        failed_checks[str(name)] += 1

    coverage_failures = [
        {
            "chapter_revision_id": target.chapter_revision_id,
            "viewport": viewport,
            "actual": route_viewport_counts[(target.chapter_revision_id, viewport)],
            "expected": expected_per_group,
        }
        for target in targets
        for viewport in viewports
        if route_viewport_counts[(target.chapter_revision_id, viewport)]
        != expected_per_group
    ]
    distributions = {}
    for group, values in sorted(ready_groups.items()):
        distributions[group] = {
            "count": len(values),
            "min_ms": round(min(values), 3),
            "p50_ms": _percentile(values, 0.50),
            "p95_ms": _percentile(values, 0.95),
            "p99_ms": _percentile(values, 0.99),
            "max_ms": round(max(values), 3),
        }
    return {
        "threshold_ms": threshold_ms,
        "target_count": len(targets),
        "viewport_count": len(viewports),
        "cold_runs_per_route_viewport": cold_runs,
        "hot_runs_per_route_viewport": hot_runs,
        "expected_sample_count": expected_samples,
        "actual_sample_count": len(samples),
        "unique_sample_count": len(unique_sample_ids),
        "coverage_failures": coverage_failures,
        "failed_sample_count": len(failed_ids),
        "failed_sample_ids": failed_ids,
        "failed_checks": dict(sorted(failed_checks.items())),
        "ready_distributions": distributions,
        "passed": (
            len(samples) == expected_samples
            and len(unique_sample_ids) == expected_samples
            and not coverage_failures
            and not failed_ids
        ),
    }


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _choose_browser_executable(explicit: Path | None) -> Path | None:
    if explicit is not None:
        resolved = explicit.resolve()
        if not resolved.is_file():
            raise GateContractError(f"browser executable does not exist: {resolved}")
        return resolved
    for candidate in (DEFAULT_CHROME, DEFAULT_EDGE):
        if candidate.is_file():
            return candidate
    return None


def _launch_browser(playwright: Any, executable: Path | None) -> Browser:
    options: dict[str, Any] = {
        "headless": True,
        "args": [
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--metrics-recording-only",
            "--no-first-run",
        ],
    }
    if executable is not None:
        options["executable_path"] = str(executable)
    return playwright.chromium.launch(**options)


def _browser_context(
    browser: Browser, viewport: Mapping[str, int]
) -> tuple[BrowserContext, Page, Any]:
    context = browser.new_context(
        viewport={"width": viewport["width"], "height": viewport["height"]},
        locale="zh-CN",
        color_scheme="light",
        reduced_motion="reduce",
        service_workers="block",
    )
    context.add_init_script(_READY_INIT_SCRIPT)
    page = context.new_page()
    cdp = context.new_cdp_session(page)
    cdp.send("Network.enable")
    cdp.send("Network.setCacheDisabled", {"cacheDisabled": False})
    return context, page, cdp


def _parse_viewports(value: str) -> list[str]:
    names = [item.strip() for item in value.split(",") if item.strip()]
    if not names or len(names) != len(set(names)):
        raise argparse.ArgumentTypeError("viewports must be a unique comma-separated list")
    unknown = [name for name in names if name not in DEFAULT_VIEWPORTS]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown viewports: {unknown}")
    return names


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify all Q2/Q5 semantic chapter routes in real Chromium."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--browser-executable", type=Path)
    parser.add_argument(
        "--viewports", type=_parse_viewports, default=["desktop", "narrow"]
    )
    parser.add_argument("--cold-runs", type=int, default=1)
    parser.add_argument("--hot-runs", type=int, default=3)
    parser.add_argument("--threshold-ms", type=float, default=1500.0)
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--expected-chapters", type=int, default=58)
    parser.add_argument("--failure-screenshot-limit", type=int, default=20)
    return parser.parse_args(argv)


def _validate_args(args: argparse.Namespace) -> tuple[Path, Path, str]:
    project_root = args.project_root.resolve()
    if not (project_root / "AGENTS.md").is_file():
        raise GateContractError(f"project root has no AGENTS.md: {project_root}")
    output_dir = args.output_dir.resolve()
    gate_root = (project_root / "project_state" / "gates").resolve()
    try:
        output_dir.relative_to(gate_root)
    except ValueError as error:
        raise GateContractError("output-dir must be inside project_state/gates") from error
    if output_dir.exists() and any(output_dir.iterdir()):
        raise GateContractError(
            "output-dir must be new or empty; immutable gate evidence is never overwritten"
        )
    if args.cold_runs < 1 or args.hot_runs < 3:
        raise GateContractError("gate requires at least one cold and three hot runs")
    if args.threshold_ms <= 0 or args.timeout_ms <= args.threshold_ms:
        raise GateContractError("timeout-ms must be greater than positive threshold-ms")
    if args.expected_chapters < 1:
        raise GateContractError("expected-chapters must be positive")
    if args.failure_screenshot_limit < 0:
        raise GateContractError("failure-screenshot-limit cannot be negative")
    parsed = urlparse(args.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise GateContractError("base-url must be an absolute HTTP(S) URL")
    return project_root, output_dir, args.base_url.rstrip("/")


def run_gate(args: argparse.Namespace) -> dict[str, Any]:
    project_root, output_dir, base_url = _validate_args(args)
    output_dir.mkdir(parents=True, exist_ok=False)
    report_path = output_dir / "report.json"
    checkpoint_path = output_dir / "checkpoint.json"
    manifest_root = (
        project_root
        / "quant_hub"
        / "src"
        / "quant_hub"
        / "presentation"
        / "chapter_manifests"
    )
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "started_at": _utc_now(),
        "finished_at": None,
        "status": "FAIL",
        "base_url": base_url,
        "contract": {
            "research_slugs": list(TARGET_RESEARCH_SLUGS),
            "expected_chapters": args.expected_chapters,
            "viewports": {
                name: DEFAULT_VIEWPORTS[name] for name in args.viewports
            },
            "cold_runs": args.cold_runs,
            "hot_runs": args.hot_runs,
            "ready_threshold_ms": args.threshold_ms,
            "navigation_timeout_ms": args.timeout_ms,
            "ready_event": "research:ready",
        },
        "manifest": None,
        "discovery": None,
        "samples": [],
        "summary": None,
        "stability": None,
        "fatal_error": None,
    }
    samples: list[dict[str, Any]] = []
    targets: list[BrowserTarget] = []
    failure_screenshots = 0
    try:
        expected, manifest_identity = load_expected_chapters(
            manifest_root,
            expected_count=args.expected_chapters,
        )
        report["manifest"] = manifest_identity
        targets, discovery_identity = discover_targets(
            base_url,
            expected,
            timeout_seconds=args.timeout_ms / 1000,
        )
        report["discovery"] = discovery_identity
        executable = _choose_browser_executable(args.browser_executable)
        report["browser"] = {
            "executable": str(executable) if executable is not None else "playwright-bundled",
        }

        with sync_playwright() as playwright:
            browser = _launch_browser(playwright, executable)
            try:
                report["browser"]["version"] = browser.version
                for viewport_name in args.viewports:
                    context, page, cdp = _browser_context(
                        browser, DEFAULT_VIEWPORTS[viewport_name]
                    )
                    try:
                        for target_index, target in enumerate(targets, start=1):
                            # Chromium's network cache is explicitly emptied for
                            # every cold sample.  That cold navigation then warms
                            # the same context for the three required hot repeats.
                            sample_specs = [
                                ("cold", run) for run in range(1, args.cold_runs + 1)
                            ] + [
                                ("hot", run) for run in range(1, args.hot_runs + 1)
                            ]
                            for cache_state, run_number in sample_specs:
                                if cache_state == "cold":
                                    cdp.send("Network.clearBrowserCache")
                                sample = sample_page(
                                    page,
                                    base_url=base_url,
                                    target=target,
                                    viewport_name=viewport_name,
                                    cache_state=cache_state,
                                    run_number=run_number,
                                    threshold_ms=args.threshold_ms,
                                    timeout_ms=args.timeout_ms,
                                )
                                samples.append(sample)
                                if (
                                    sample["passed"] is not True
                                    and failure_screenshots
                                    < args.failure_screenshot_limit
                                ):
                                    screenshots = output_dir / "failure_screenshots"
                                    screenshots.mkdir(exist_ok=True)
                                    screenshot_name = re.sub(
                                        r"[^a-zA-Z0-9_.-]+",
                                        "_",
                                        str(sample["sample_id"]),
                                    )[:180]
                                    try:
                                        page.screenshot(
                                            path=str(screenshots / f"{screenshot_name}.png"),
                                            full_page=False,
                                        )
                                        sample["failure_screenshot"] = (
                                            f"failure_screenshots/{screenshot_name}.png"
                                        )
                                        failure_screenshots += 1
                                    except Exception as screenshot_error:
                                        sample["failure_screenshot_error"] = str(
                                            screenshot_error
                                        )
                            # A compact, atomic checkpoint after each route makes
                            # a crash auditable without treating partial evidence
                            # as a passing report.
                            _atomic_write_json(
                                checkpoint_path,
                                {
                                    "schema_version": f"{SCHEMA_VERSION}/checkpoint",
                                    "manifest_generation_id": manifest_identity[
                                        "generation_id"
                                    ],
                                    "base_url": base_url,
                                    "completed_route_viewport_groups": (
                                        target_index
                                        + len(targets) * args.viewports.index(viewport_name)
                                    ),
                                    "expected_route_viewport_groups": (
                                        len(targets) * len(args.viewports)
                                    ),
                                    "sample_count": len(samples),
                                    "last_sample_id": samples[-1]["sample_id"],
                                    "updated_at": _utc_now(),
                                },
                            )
                    finally:
                        context.close()
            finally:
                browser.close()

        summary = summarize_samples(
            samples,
            targets=targets,
            viewports=args.viewports,
            cold_runs=args.cold_runs,
            hot_runs=args.hot_runs,
            threshold_ms=args.threshold_ms,
        )
        report["summary"] = summary

        # Re-read both authorities after a long full-corpus run.  A gate over a
        # moving manifest or API release is invalid even if every sampled page
        # happened to pass individually.
        _final_expected, final_manifest_identity = load_expected_chapters(
            manifest_root,
            expected_count=args.expected_chapters,
        )
        _final_targets, final_discovery_identity = discover_targets(
            base_url,
            expected,
            timeout_seconds=args.timeout_ms / 1000,
        )
        stability = {
            "manifest_unchanged": final_manifest_identity == manifest_identity,
            "route_set_unchanged": (
                final_discovery_identity["route_set_sha256"]
                == discovery_identity["route_set_sha256"]
            ),
            "research_api_payloads_unchanged": (
                final_discovery_identity["research_list"]["data_sha256"]
                == discovery_identity["research_list"]["data_sha256"]
                and {
                    key: value["data_sha256"]
                    for key, value in final_discovery_identity[
                        "research_details"
                    ].items()
                }
                == {
                    key: value["data_sha256"]
                    for key, value in discovery_identity["research_details"].items()
                }
            ),
        }
        stability["passed"] = all(stability.values())
        report["stability"] = stability
        if summary["passed"] and stability["passed"]:
            report["status"] = "PASS"
    except Exception as error:
        report["fatal_error"] = f"{type(error).__name__}: {error}"
    finally:
        report["samples"] = samples
        if report.get("summary") is None and targets:
            report["summary"] = summarize_samples(
                samples,
                targets=targets,
                viewports=args.viewports,
                cold_runs=args.cold_runs,
                hot_runs=args.hot_runs,
                threshold_ms=args.threshold_ms,
            )
        report["finished_at"] = _utc_now()
        _atomic_write_json(report_path, report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        report = run_gate(args)
    except Exception as error:
        print(f"chapter performance gate setup failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    summary = report.get("summary")
    compact = {
        "status": report["status"],
        "report": str(args.output_dir.resolve() / "report.json"),
        "target_count": summary.get("target_count") if isinstance(summary, Mapping) else None,
        "sample_count": summary.get("actual_sample_count") if isinstance(summary, Mapping) else None,
        "failed_samples": summary.get("failed_sample_count") if isinstance(summary, Mapping) else None,
        "fatal_error": report.get("fatal_error"),
    }
    print(json.dumps(compact, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
