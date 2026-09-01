"""Authenticated, read-only route and latency gate for production loopback HTTP.

The gate never submits the login form and never sends a mutating request.  It
derives the exact Flask access-gate session cookie locally from the protected
session secret and password digest, then performs only GET requests.  Reports
contain response hashes and timing metadata, never either protected input or
the resulting cookie.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from typing import Iterable, Iterator, Mapping, Sequence
from urllib.error import HTTPError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flask import Flask


SCHEMA_VERSION = "qrh-authenticated-route-performance-gate/v1"
DEFAULT_VM_ROOT = Path(r"D:\quant\quant_platform")
DEFAULT_BASE_URL = "http://127.0.0.1:8765"
DEFAULT_THRESHOLD_MS = 2_000.0
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_ROUTES = 20_000
DEFAULT_MAX_DISCOVERY_BYTES = 64 * 1024 * 1024
COOKIE_NAME = "quant_hub_broadcast_session"
ACCESS_SESSION_KEY = "quant_hub_broadcast_authenticated"
ACCESS_SESSION_MARKER_PREFIX = "pbkdf2-sha256-v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_CITATION_ID = re.compile(r"^cit_[a-z2-7]{52}$")
_SAFE_DYNAMIC_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_URL_KEYS = frozenset(
    {
        "api_url",
        "detail_url",
        "download_url",
        "href",
        "local_url",
        "page_url",
        "resource_url",
        "source_url",
        "url",
    }
)
_SEEDS = (
    "/",
    "/deploymentz",
    "/healthz",
    "/research-updates",
    "/evidence/",
    "/paper-lab/",
    "/paper-lab/designer",
    "/api/v1/session",
    "/api/v1/research-tree",
    "/api/v1/research",
    "/api/v1/dashboard",
    "/api/v1/research-updates",
    "/api/v1/search?q=research",
    "/api/v1/topics",
    "/api/v1/dashboard-topics",
    "/api/v1/evidence/papers?limit=500",
    "/api/v1/paper-lab/papers?limit=1000",
    "/api/v1/paper-lab/components",
    "/api/v1/paper-lab/blueprints",
)

# Every GET rule registered by create_app(), plus the production-only
# /deploymentz rule installed by service_entry.  The unit test compares this
# contract with Flask's url_map so a new GET surface cannot silently fall out of
# the crawler.  Runtime instances are supplied by seeds, HTML/JSON discovery or
# the sealed generic-release snapshot.
GET_ROUTE_COVERAGE_CONTRACT = {
    "/": "seed",
    "/api/v1/archive/assets/<asset_id>": "json_asset_id",
    "/api/v1/dashboard": "seed",
    "/api/v1/dashboard-topics": "seed",
    "/api/v1/dashboard-topics/<topic_id>": "management_json_topic_id",
    "/api/v1/evidence/citation-entries/<ledger_entry_id>": "evidence_json_id",
    "/api/v1/evidence/citations/<citation_id>": "evidence_json_id",
    "/api/v1/evidence/documents/<document_sha256>/citations": "evidence_json_id",
    "/api/v1/evidence/papers": "seed",
    "/api/v1/evidence/papers/<paper_id>": "evidence_json_id",
    "/api/v1/evidence/resources/<resource_id>": "evidence_json_id",
    "/api/v1/paper-lab/blueprints": "seed",
    "/api/v1/paper-lab/blueprints/<blueprint_id>": "paper_lab_json_id",
    "/api/v1/paper-lab/components": "seed",
    "/api/v1/paper-lab/notes/<note_id>/content": "paper_lab_json_id",
    "/api/v1/paper-lab/papers": "seed",
    "/api/v1/paper-lab/papers/<paper_id>": "paper_lab_json_id",
    "/api/v1/paper-lab/versions/<paper_version_id>/content": "paper_lab_json_id",
    "/api/v1/research": "seed",
    "/api/v1/research-nodes/<node_id>": "research_tree_json_id",
    "/api/v1/research-nodes/<node_id>/comments": "research_tree_json_id",
    "/api/v1/research-tree": "seed",
    "/api/v1/research-updates": "seed",
    "/api/v1/research/<research_id>": "research_json_id",
    "/api/v1/research/<research_id>/comments": "research_json_id",
    "/api/v1/research/<research_id>/documents/<document_id>/source": "json_url_or_html",
    "/api/v1/search": "seed_with_query",
    "/api/v1/session": "seed",
    "/api/v1/topics": "seed",
    "/deploymentz": "seed_and_identity_binding",
    "/evidence/": "seed",
    "/evidence/citations/<citation_id>": "evidence_json_id_or_html_marker",
    "/evidence/library/<paper_id>.pdf": "json_url",
    "/evidence/papers/<paper_id>": "evidence_json_id",
    "/evidence/static/<path:filename>": "html_src_or_href",
    "/healthz": "seed",
    "/knowledge/<path:logical_path>": "generic_internal_link_redirect",
    "/knowledge/assets/<path:filename>": "generic_html_src_or_href",
    "/knowledge/link/<document_id>/<version_id>": "generic_rendered_content_url",
    "/knowledge/research/<document_id>/": "sealed_generic_snapshot",
    "/knowledge/research/<document_id>/versions/<version_id>/": "sealed_generic_snapshot",
    "/knowledge/research/<document_id>/versions/<version_id>/source": "sealed_generic_snapshot",
    "/paper-lab/": "seed",
    "/paper-lab/designer": "seed",
    "/paper-lab/papers/<paper_id>": "paper_lab_json_id",
    "/paper-lab/static/<path:filename>": "html_src_or_href",
    "/research-updates": "seed",
    "/research/<research_id>": "research_json_id",
    "/research/<research_id>/documents/<document_id>": "html_href_or_json_url",
    "/research/<research_id>/documents/<document_id>/chapters/<chapter_slug>": "html_href_or_json_url",
    "/research/<research_id>/supplements/<supplement_id>": "html_href_or_json_url",
    "/research/<research_id>/supplements/<supplement_id>/source": "html_href_or_json_url",
    "/static/<path:filename>": "html_src_or_href",
}


class GateError(RuntimeError):
    """The target, protected inputs, or route graph violated the gate."""


@dataclass(frozen=True, slots=True)
class RouteSample:
    route: str
    discovered_from: tuple[str, ...]
    final_url: str | None
    status_code: int | None
    elapsed_ms: float
    response_bytes: int
    response_sha256: str | None
    content_type: str | None
    discovered_route_count: int
    outcome: str
    error: str | None = None


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: set[str] = set()
        self.citation_ids: set[str] = set()

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = {name.casefold(): value for name, value in attrs}
        for name, value in attrs:
            if not value:
                continue
            folded = name.casefold()
            if folded in {"href", "src"}:
                self.references.add(value.strip())
            elif folded == "data-citation-id" and _CITATION_ID.fullmatch(value):
                self.citation_ids.add(value)
        if tag.casefold() == "form":
            method = (attributes.get("method") or "get").strip().casefold()
            action = (attributes.get("action") or "").strip()
            if method == "get" and action:
                self.references.add(action)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(getattr(info, "st_nlink", 1)),
    )


def _read_protected_hex(path: Path, *, label: str) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"{label} is unavailable") from error
    if (
        _is_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or getattr(before, "st_nlink", 1) != 1
        or not 1 <= before.st_size <= 128
    ):
        raise GateError(f"{label} is not a bounded regular single-link file")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise GateError(f"{label} could not be read") from error
    if _file_identity(before) != _file_identity(after):
        raise GateError(f"{label} changed while being read")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise GateError(f"{label} is not ASCII") from error
    if _HEX_64.fullmatch(value) is None:
        raise GateError(f"{label} is not the required 64-character hex value")
    return value


def _read_stable_bounded(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"{label} is unavailable") from error
    if (
        _is_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or not 1 <= before.st_size <= max_bytes
    ):
        raise GateError(f"{label} is not a bounded regular file")
    try:
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise GateError(f"{label} could not be read") from error
    if _file_identity(before) != _file_identity(after):
        raise GateError(f"{label} changed while being read")
    return raw


def _generic_release_routes(
    vm_root: Path,
    release_id: str,
) -> tuple[set[str], dict[str, object]]:
    release_root = (vm_root / "releases" / release_id).resolve(strict=True)
    try:
        release_root.relative_to(vm_root)
    except ValueError as error:
        raise GateError("expected release escapes the VM project root") from error
    snapshot_path = release_root / "content" / "deterministic_snapshot.json"
    if not snapshot_path.is_file():
        return set(), {"present": False, "route_count": 0}
    raw = _read_stable_bounded(
        snapshot_path,
        label="generic deterministic snapshot",
        max_bytes=128 * 1024 * 1024,
    )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError("generic deterministic snapshot is not UTF-8 JSON") from error
    if not isinstance(value, Mapping) or not isinstance(value.get("snapshot"), Mapping):
        raise GateError("generic deterministic snapshot envelope is invalid")
    snapshot = value["snapshot"]
    documents = snapshot.get("documents")
    if not isinstance(documents, Mapping):
        raise GateError("generic deterministic snapshot has no document mapping")
    routes: set[str] = set()
    document_count = 0
    version_count = 0
    for key, item in documents.items():
        if not isinstance(item, Mapping):
            raise GateError("generic deterministic snapshot document is invalid")
        document_id = _safe_id(item.get("document_id"))
        version_ids = item.get("version_ids")
        if (
            document_id is None
            or str(key) != str(item.get("document_id"))
            or not isinstance(version_ids, list)
        ):
            raise GateError("generic deterministic snapshot document identity is invalid")
        routes.add(f"/knowledge/research/{document_id}/")
        document_count += 1
        for raw_version_id in version_ids:
            version_id = _safe_id(raw_version_id)
            if version_id is None:
                raise GateError("generic deterministic snapshot version identity is invalid")
            routes.update(
                {
                    f"/knowledge/research/{document_id}/versions/{version_id}/",
                    f"/knowledge/research/{document_id}/versions/{version_id}/source",
                }
            )
            version_count += 1
    return routes, {
        "present": True,
        "snapshot_id": str(snapshot.get("snapshot_id") or ""),
        "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
        "document_count": document_count,
        "version_count": version_count,
        "route_count": len(routes),
    }


def _validate_deployment_identity(
    value: object,
    *,
    expected_release_id: str,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise GateError("deploymentz did not return an object")
    if value.get("schema_version") != "qrh-service-deployment-health/v1":
        raise GateError("deploymentz schema is invalid")
    if value.get("status") != "ok":
        raise GateError("deploymentz status is not ok")
    if value.get("release_id") != expected_release_id:
        raise GateError("deploymentz release identity differs from the expected release")
    if value.get("manifest_sha256") != expected_manifest_sha256:
        raise GateError("deploymentz manifest identity differs from the expected manifest")
    snapshot_id = value.get("snapshot_id")
    writer_authority = value.get("writer_authority")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise GateError("deploymentz snapshot identity is missing")
    if not isinstance(writer_authority, str) or not writer_authority:
        raise GateError("deploymentz writer authority is missing")
    if not isinstance(value.get("pid"), int) or not isinstance(value.get("port"), int):
        raise GateError("deploymentz process identity is invalid")
    return {
        "schema_version": value["schema_version"],
        "status": value["status"],
        "release_id": value["release_id"],
        "manifest_sha256": value["manifest_sha256"],
        "snapshot_id": snapshot_id,
        "writer_authority": writer_authority,
        "pid": value["pid"],
        "port": value["port"],
    }


def _build_cookie(session_secret: str, password_digest_hex: str) -> str:
    expected_digest = bytes.fromhex(password_digest_hex)
    marker = ACCESS_SESSION_MARKER_PREFIX + ":" + hashlib.sha256(
        expected_digest
    ).hexdigest()[:24]
    app = Flask("qrh_authenticated_route_performance_gate")
    app.config.update(
        SECRET_KEY=session_secret,
        SESSION_COOKIE_NAME=COOKIE_NAME,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
    )
    serializer = app.session_interface.get_signing_serializer(app)
    if serializer is None:
        raise GateError("Flask session serializer is unavailable")
    value = serializer.dumps({ACCESS_SESSION_KEY: marker})
    if not isinstance(value, str) or not value:
        raise GateError("Flask session serializer returned an invalid cookie")
    return value


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise GateError("base URL must be an absolute HTTP(S) URL")
    host = parsed.hostname.casefold()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise GateError("base URL must use a loopback host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise GateError("base URL must not contain credentials, query, or fragment")
    return parsed.scheme.casefold(), host, port


def _canonical_route(
    base_url: str,
    reference: str,
    *,
    document_url: str | None = None,
) -> str | None:
    candidate = reference.strip()
    if not candidate or candidate.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
        return None
    try:
        resolution_base = document_url or (base_url.rstrip("/") + "/")
        absolute = urlsplit(urljoin(resolution_base, candidate))
    except ValueError:
        return None
    if absolute.username or absolute.password:
        return None
    try:
        candidate_origin = (
            absolute.scheme.casefold(),
            (absolute.hostname or "").casefold(),
            absolute.port or (443 if absolute.scheme == "https" else 80),
        )
    except ValueError:
        return None
    if candidate_origin != _origin(base_url):
        return None
    path = absolute.path or "/"
    if path in {"/login", "/logout"}:
        return None
    return urlunsplit(("", "", path, absolute.query, ""))


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self._base_origin = _origin(base_url)

    def redirect_request(  # type: ignore[override]
        self,
        request: Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: Mapping[str, str],
        new_url: str,
    ) -> Request | None:
        parsed = urlsplit(new_url)
        target = (
            parsed.scheme.casefold(),
            (parsed.hostname or "").casefold(),
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        if target != self._base_origin:
            raise GateError("same-origin route redirected outside the loopback origin")
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def _iter_key_values(value: object) -> Iterator[tuple[str, object]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            rendered = str(key)
            yield rendered, child
            yield from _iter_key_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_key_values(child)


def _safe_id(value: object) -> str | None:
    if not isinstance(value, str) or _SAFE_DYNAMIC_ID.fullmatch(value) is None:
        return None
    return quote(value, safe="")


def _json_routes(
    base_url: str,
    route: str,
    value: object,
    *,
    document_url: str | None = None,
) -> set[str]:
    discovered: set[str] = set()
    pairs = tuple(_iter_key_values(value))
    for key, child in pairs:
        folded = key.casefold()
        if (
            folded in _URL_KEYS or folded.endswith("_url")
        ) and isinstance(child, str):
            candidate = _canonical_route(
                base_url, child, document_url=document_url
            )
            if candidate is not None:
                discovered.add(candidate)

    if route.startswith("/api/v1/research-tree"):
        for key, child in pairs:
            identifier = _safe_id(child) if key == "node_id" else None
            if identifier:
                discovered.update(
                    {
                        f"/api/v1/research-nodes/{identifier}",
                        f"/api/v1/research-nodes/{identifier}/comments",
                    }
                )

    if route == "/api/v1/research" or route.startswith("/api/v1/research?"):
        for key, child in pairs:
            identifier = _safe_id(child) if key == "research_id" else None
            if identifier:
                discovered.update(
                    {
                        f"/research/{identifier}",
                        f"/api/v1/research/{identifier}",
                        f"/api/v1/research/{identifier}/comments",
                    }
                )

    # Only management-list topic ids are valid inputs to the management detail
    # endpoint.  The public dashboard/topic projections also contain generated
    # topic ids which intentionally have no management-detail representation.
    if route == "/api/v1/dashboard-topics" or route.startswith(
        "/api/v1/dashboard-topics?"
    ):
        for key, child in pairs:
            identifier = _safe_id(child) if key == "topic_id" else None
            if identifier:
                discovered.add(f"/api/v1/dashboard-topics/{identifier}")

    if route.startswith("/api/v1/evidence/"):
        for key, child in pairs:
            identifier = _safe_id(child)
            if not identifier:
                continue
            if key == "paper_id":
                discovered.update(
                    {
                        f"/evidence/papers/{identifier}",
                        f"/api/v1/evidence/papers/{identifier}",
                    }
                )
            elif key == "citation_id":
                discovered.update(
                    {
                        f"/evidence/citations/{identifier}",
                        f"/api/v1/evidence/citations/{identifier}",
                    }
                )
            elif key == "ledger_entry_id":
                discovered.add(
                    f"/api/v1/evidence/citation-entries/{identifier}"
                )
            elif key == "resource_id":
                discovered.add(f"/api/v1/evidence/resources/{identifier}")

    if route.startswith("/api/v1/paper-lab/"):
        for key, child in pairs:
            identifier = _safe_id(child)
            if not identifier:
                continue
            # Component payloads preserve numeric legacy proj2 paper ids beside
            # current Paper Lab ids.  Only the latter address Paper Lab routes.
            if key == "paper_id" and str(child).startswith("labpaper_"):
                discovered.update(
                    {
                        f"/paper-lab/papers/{identifier}",
                        f"/api/v1/paper-lab/papers/{identifier}",
                    }
                )
            elif key == "paper_version_id":
                discovered.add(
                    f"/api/v1/paper-lab/versions/{identifier}/content"
                )
            elif key == "note_id":
                discovered.add(f"/api/v1/paper-lab/notes/{identifier}/content")
            elif key == "blueprint_id":
                discovered.add(f"/api/v1/paper-lab/blueprints/{identifier}")

    for key, child in pairs:
        identifier = _safe_id(child)
        if not identifier:
            continue
        if key == "document_sha256" and _HEX_64.fullmatch(str(child)):
            discovered.add(
                f"/api/v1/evidence/documents/{identifier}/citations"
            )
        elif key == "asset_id":
            discovered.add(f"/api/v1/archive/assets/{identifier}")
    return discovered


def _html_routes(base_url: str, document_url: str, body: bytes) -> set[str]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError("HTML response is not UTF-8") from error
    parser = _LinkParser()
    parser.feed(text)
    parser.close()
    routes = {
        candidate
        for reference in parser.references
        if (
            candidate := _canonical_route(
                base_url, reference, document_url=document_url
            )
        )
        is not None
    }
    for citation_id in parser.citation_ids:
        identifier = quote(citation_id, safe="")
        routes.update(
            {
                f"/evidence/citations/{identifier}",
                f"/api/v1/evidence/citations/{identifier}",
            }
        )
    return routes


def _atomic_write_json(path: Path, value: object, *, vm_root: Path) -> None:
    root = vm_root.resolve(strict=True)
    destination = path.resolve(strict=False)
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise GateError("output path must remain inside the VM project root") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _failure_sample(
    route: str,
    sources: Iterable[str],
    *,
    started: float,
    error: BaseException,
    status_code: int | None = None,
) -> RouteSample:
    return RouteSample(
        route=route,
        discovered_from=tuple(sorted(sources)),
        final_url=None,
        status_code=status_code,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        response_bytes=0,
        response_sha256=None,
        content_type=None,
        discovered_route_count=0,
        outcome="FAIL",
        error=f"{type(error).__name__}: {error}",
    )


def run_gate(args: argparse.Namespace) -> dict[str, object]:
    started_at = _utc_now()
    base_url = args.base_url.rstrip("/")
    _origin(base_url)
    vm_root = args.vm_root.resolve(strict=True)
    gate_tool_sha256 = hashlib.sha256(
        _read_stable_bounded(
            Path(__file__).resolve(strict=True),
            label="performance gate tool",
            max_bytes=2 * 1024 * 1024,
        )
    ).hexdigest()
    generic_routes, generic_coverage = _generic_release_routes(
        vm_root, args.expected_release_id
    )
    session_path = (
        args.session_secret
        if args.session_secret is not None
        else vm_root / "state" / "viewer_secret.key"
    )
    digest_path = (
        args.password_digest
        if args.password_digest is not None
        else vm_root / "state" / "viewer_access_password.digest"
    )
    for protected in (session_path, digest_path):
        try:
            protected.resolve(strict=True).relative_to(vm_root)
        except (OSError, ValueError) as error:
            raise GateError("protected authentication input is outside VM root") from error
    session_secret = _read_protected_hex(session_path, label="session secret")
    password_digest = _read_protected_hex(digest_path, label="password digest")
    cookie = _build_cookie(session_secret, password_digest)
    # Do not retain an additional password digest string after cookie construction.
    session_secret = ""
    password_digest = ""

    opener = build_opener(_SameOriginRedirectHandler(base_url))
    queue: deque[str] = deque()
    sources: dict[str, set[str]] = {}
    completed: set[str] = set()

    def enqueue(reference: str, source: str) -> None:
        route = _canonical_route(base_url, reference)
        if route is None:
            return
        origins = sources.setdefault(route, set())
        origins.add(source)
        if route not in completed and route not in queue:
            queue.append(route)

    for seed in _SEEDS:
        enqueue(seed, "seed")
    for seed in args.seed:
        enqueue(seed, "cli_seed")
    for route in sorted(generic_routes):
        enqueue(route, "sealed_generic_snapshot")

    samples: list[RouteSample] = []
    deployment_identity: dict[str, object] | None = None
    while queue and len(completed) < args.max_routes:
        route = queue.popleft()
        if route in completed:
            continue
        completed.add(route)
        absolute = urljoin(base_url + "/", route.lstrip("/"))
        request = Request(
            absolute,
            method="GET",
            headers={
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Cookie": f"{COOKIE_NAME}={cookie}",
                "User-Agent": "QuantResearchHub-AuthenticatedRoutePerformanceGate/1",
            },
        )
        started = time.perf_counter()
        response = None
        try:
            response = opener.open(request, timeout=args.timeout_seconds)
            status = int(response.status)
            final_url = str(response.url)
            if response.headers.get("X-Quant-Hub-Release") != args.expected_release_id:
                raise GateError("response release header differs from expected release")
            if urlsplit(final_url).path == "/login":
                raise GateError("authenticated request returned to the login surface")
            final_route = _canonical_route(base_url, final_url)
            if final_route is None:
                raise GateError("response escaped the loopback origin")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()
            retain = content_type in {
                "application/json",
                "application/problem+json",
                "text/html",
            }
            chunks: list[bytes] = []
            retained = 0
            observed = 0
            digest = hashlib.sha256()
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                digest.update(chunk)
                if retain:
                    retained += len(chunk)
                    if retained > args.max_discovery_bytes:
                        raise GateError(
                            "HTML/JSON response exceeds the discovery byte limit"
                        )
                    chunks.append(chunk)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            body = b"".join(chunks) if retain else b""
            discovered: set[str] = set()
            if content_type == "text/html":
                discovered = _html_routes(base_url, final_url, body)
            elif content_type in {"application/json", "application/problem+json"}:
                try:
                    value = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise GateError("JSON response is not valid UTF-8 JSON") from error
                if route == "/deploymentz":
                    deployment_identity = _validate_deployment_identity(
                        value,
                        expected_release_id=args.expected_release_id,
                        expected_manifest_sha256=args.expected_manifest_sha256,
                    )
                discovered = _json_routes(
                    base_url,
                    route,
                    value,
                    document_url=final_url,
                )
            for candidate in sorted(discovered):
                enqueue(candidate, route)
            outcome = (
                "PASS"
                if 200 <= status < 400 and elapsed_ms < args.threshold_ms
                else "FAIL"
            )
            error = None
            if status >= 400:
                error = f"HTTP status {status}"
            elif elapsed_ms >= args.threshold_ms:
                error = (
                    f"elapsed {elapsed_ms:.3f} ms is not below "
                    f"{args.threshold_ms:.3f} ms"
                )
            samples.append(
                RouteSample(
                    route=route,
                    discovered_from=tuple(sorted(sources.get(route, ()))),
                    final_url=final_url,
                    status_code=status,
                    elapsed_ms=elapsed_ms,
                    response_bytes=observed,
                    response_sha256=digest.hexdigest(),
                    content_type=content_type or None,
                    discovered_route_count=len(discovered),
                    outcome=outcome,
                    error=error,
                )
            )
        except HTTPError as error:
            samples.append(
                _failure_sample(
                    route,
                    sources.get(route, ()),
                    started=started,
                    error=error,
                    status_code=int(error.code),
                )
            )
        except Exception as error:
            samples.append(
                _failure_sample(
                    route,
                    sources.get(route, ()),
                    started=started,
                    error=error,
                )
            )
        finally:
            if response is not None:
                response.close()

    if queue:
        samples.append(
            RouteSample(
                route="<route-limit>",
                discovered_from=("gate",),
                final_url=None,
                status_code=None,
                elapsed_ms=0.0,
                response_bytes=0,
                response_sha256=None,
                content_type=None,
                discovered_route_count=len(queue),
                outcome="FAIL",
                error=f"route graph exceeds max_routes={args.max_routes}",
            )
        )

    if deployment_identity is None:
        samples.append(
            RouteSample(
                route="<deployment-identity>",
                discovered_from=("gate",),
                final_url=None,
                status_code=None,
                elapsed_ms=0.0,
                response_bytes=0,
                response_sha256=None,
                content_type=None,
                discovered_route_count=0,
                outcome="FAIL",
                error="production deployment identity was not verified",
            )
        )

    failed = [sample for sample in samples if sample.outcome != "PASS"]
    elapsed_values = sorted(
        sample.elapsed_ms for sample in samples if sample.route != "<route-limit>"
    )
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if not failed else "FAIL",
        "started_at": started_at,
        "finished_at": _utc_now(),
        "base_url": base_url,
        "method": "GET_ONLY",
        "authentication": {
            "scheme": "locally_signed_flask_session",
            "cookie_name": COOKIE_NAME,
            "protected_values_in_report": False,
        },
        "gate_tool_sha256": gate_tool_sha256,
        "deployment_identity": deployment_identity,
        "coverage_contract": {
            "schema_version": "qrh-get-route-coverage-contract/v1",
            "declared_get_rules": dict(sorted(GET_ROUTE_COVERAGE_CONTRACT.items())),
            "declared_get_rule_count": len(GET_ROUTE_COVERAGE_CONTRACT),
            "fixed_seed_count": len(_SEEDS),
            "generic_release": generic_coverage,
        },
        "threshold_ms": args.threshold_ms,
        "timeout_seconds": args.timeout_seconds,
        "route_count": len(completed),
        "sample_count": len(samples),
        "failed_sample_count": len(failed),
        "max_elapsed_ms": max(elapsed_values, default=0.0),
        "samples": [asdict(sample) for sample in samples],
        "route_set_sha256": hashlib.sha256(
            json.dumps(
                sorted(completed), ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest(),
    }
    return report


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only authenticated loopback crawler; every GET must finish "
            "strictly below the latency threshold."
        )
    )
    parser.add_argument("--vm-root", type=Path, default=DEFAULT_VM_ROOT)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--session-secret", type=Path)
    parser.add_argument("--password-digest", type=Path)
    parser.add_argument("--threshold-ms", type=float, default=DEFAULT_THRESHOLD_MS)
    parser.add_argument(
        "--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("--max-routes", type=int, default=DEFAULT_MAX_ROUTES)
    parser.add_argument(
        "--max-discovery-bytes",
        type=int,
        default=DEFAULT_MAX_DISCOVERY_BYTES,
    )
    parser.add_argument(
        "--seed",
        action="append",
        default=[],
        help="Additional same-origin GET route; may be repeated.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional canonical JSON evidence path; must be inside --vm-root.",
    )
    args = parser.parse_args(argv)
    if _SAFE_DYNAMIC_ID.fullmatch(args.expected_release_id) is None:
        parser.error("--expected-release-id is invalid")
    if _HEX_64.fullmatch(args.expected_manifest_sha256) is None:
        parser.error("--expected-manifest-sha256 must be lowercase 64-character hex")
    if args.threshold_ms <= 0:
        parser.error("--threshold-ms must be positive")
    if args.timeout_seconds <= args.threshold_ms / 1000:
        parser.error("--timeout-seconds must exceed --threshold-ms")
    if args.max_routes < len(_SEEDS):
        parser.error(f"--max-routes must be at least {len(_SEEDS)}")
    if args.max_discovery_bytes < 1024:
        parser.error("--max-discovery-bytes must be at least 1024")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = run_gate(args)
        if args.output is not None:
            _atomic_write_json(args.output, report, vm_root=args.vm_root)
    except Exception as error:
        # Protected input values and the derived cookie are never interpolated.
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "status": "FAIL",
                    "error": f"{type(error).__name__}: {error}",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    compact = {
        "schema_version": SCHEMA_VERSION,
        "status": report["status"],
        "route_count": report["route_count"],
        "failed_sample_count": report["failed_sample_count"],
        "max_elapsed_ms": report["max_elapsed_ms"],
        "output": str(args.output.resolve()) if args.output is not None else None,
    }
    print(json.dumps(compact, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
