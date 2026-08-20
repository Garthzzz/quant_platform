"""把当前冻结前端的研究页面导出为人工修订用 Markdown 工作区。

导出文件只是一份离线修订副本：运行时不会读取它，修改也不会自动更新前端。
每一页保留来源 Markdown 的完整内容，并按前端章节 manifest 切分；展示层标题
覆盖会投影到 Markdown 标题，便于研究员看到与前端一致的专业命名。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import sys
import uuid
from typing import Any, Iterable, Mapping, Sequence


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
DEFAULT_ARCHIVE_ROOT = WORKSPACE_ROOT / "reference" / "archive"
DEFAULT_OUTPUT_ROOT = WORKSPACE_ROOT / "研究修订工作区"
COPY_MARKER = "QRH_RESEARCH_REVISION_COPY_V1"
MANIFEST_SCHEMA = "qrh-research-revision-workspace/v1"
WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
INVALID_WINDOWS_CHARS = str.maketrans(
    {
        '<': "＜",
        '>': "＞",
        ':': "：",
        '"': "”",
        '/': "／",
        '\\': "＼",
        '|': "｜",
        '?': "？",
        '*': "＊",
    }
)
ATX_HEADING_RE = re.compile(
    r"^(?P<indent>[ \t]{0,3})(?P<marks>#{1,6})(?P<gap>[ \t]+)"
    r"(?P<title>.*?)(?P<closing>[ \t]+#+[ \t]*)?(?P<eol>\r?\n)?$"
)
FENCE_RE = re.compile(r"^[ \t]{0,3}(?P<fence>`{3,}|~{3,})")


class RevisionWorkspaceError(RuntimeError):
    """导出输入、路径或完整性不满足约束。"""


@dataclass(frozen=True)
class ActiveDocument:
    research_slug: str
    research_id: str
    document_id: str
    document_slug: str
    source_path: str
    source_sha256: str
    source_bytes: int
    sort_key: int


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def safe_component(value: str, *, max_chars: int) -> str:
    """生成保留中文可读性的 Windows 安全路径组件。"""

    normalized = re.sub(r"\s+", " ", value.strip()).translate(INVALID_WINDOWS_CHARS)
    normalized = normalized.rstrip(" .") or "未命名"
    if normalized.upper() in WINDOWS_RESERVED:
        normalized = f"_{normalized}"
    if len(normalized) > max_chars:
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:8]
        normalized = f"{normalized[: max_chars - 10].rstrip()}…-{digest}"
    return normalized


def numbered_component(ordinal: int, title: str, *, max_chars: int) -> str:
    return f"{ordinal:02d}_{safe_component(title, max_chars=max_chars)}"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_roots(
    *, project_root: Path, archive_root: Path, delivery_var: Path, output_root: Path
) -> None:
    project = project_root.resolve(strict=True)
    archive = archive_root.resolve(strict=True)
    delivery = delivery_var.resolve(strict=True)
    output = output_root.resolve(strict=False)
    if not _is_relative_to(archive, (project / "reference").resolve(strict=True)):
        raise RevisionWorkspaceError("Archive root is outside the read-only reference area")
    if not _is_relative_to(delivery, (project / "quant_hub" / "var").resolve(strict=True)):
        raise RevisionWorkspaceError("Delivery root is outside quant_hub/var")
    forbidden = (
        (project / "reference").resolve(strict=True),
        (project / "quant_hub" / "src").resolve(strict=True),
        (project / "quant_hub" / "var").resolve(strict=True),
    )
    if not _is_relative_to(output, project):
        raise RevisionWorkspaceError("Revision workspace must stay inside the project")
    if any(_is_relative_to(output, root) for root in forbidden):
        raise RevisionWorkspaceError("Revision workspace overlaps a protected/runtime area")
    if output.exists():
        raise RevisionWorkspaceError(
            f"revision workspace already exists; refusing to overwrite researcher edits: {output}"
        )


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RevisionWorkspaceError(f"cannot load JSON: {path}") from error
    if not isinstance(value, dict):
        raise RevisionWorkspaceError(f"JSON root is not an object: {path}")
    return value


def load_active_chapter_manifests(presentation_root: Path) -> dict[str, dict[str, Any]]:
    root = presentation_root / "chapter_manifests"
    pointer_path = root / "active.json"
    pointer = load_json(pointer_path)
    if pointer.get("schema_version") != "qrh-archive-chapter-generation-pointer/v1":
        raise RevisionWorkspaceError("active chapter pointer schema is unsupported")
    generation_name = str(pointer.get("generation_directory", ""))
    generation = (root / "generations" / generation_name).resolve(strict=True)
    if not _is_relative_to(generation, root.resolve(strict=True)):
        raise RevisionWorkspaceError("active chapter generation escaped its root")
    files = pointer.get("files")
    if not isinstance(files, dict) or not files:
        raise RevisionWorkspaceError("active chapter pointer has no file seal map")
    for name, expected in files.items():
        path = generation / str(name)
        actual = sha256(path.read_bytes())
        if actual != expected:
            raise RevisionWorkspaceError(f"active chapter artifact hash mismatch: {name}")
    index = load_json(generation / "index.json")
    manifests: dict[str, dict[str, Any]] = {}
    for item in index.get("research", []):
        if not isinstance(item, dict):
            raise RevisionWorkspaceError("chapter index research row is invalid")
        path = generation / str(item["manifest_path"])
        manifest = load_json(path)
        slug = str(manifest.get("research_slug", ""))
        if not slug or slug in manifests:
            raise RevisionWorkspaceError("chapter research identity is missing or duplicated")
        manifests[slug] = manifest
    return manifests


def _readonly_connection(path: Path) -> sqlite3.Connection:
    uri = f"{path.resolve(strict=True).as_uri()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def load_active_documents(database: Path) -> dict[tuple[str, str], ActiveDocument]:
    """以已发布 release 与 verified archive_path origin 建立路径索引。"""

    query = """
        SELECT r.canonical_slug, r.research_id, rd.document_id,
               rd.slug AS document_slug, rri.sort_key,
               rdv.content_sha256, rdv.bytes
        FROM research AS r
        JOIN active_research_release AS active
          ON active.research_id = r.research_id
        JOIN research_release_item AS rri
          ON rri.research_release_id = active.research_release_id
        JOIN research_document AS rd
          ON rd.document_id = rri.document_id
        JOIN research_document_version AS rdv
          ON rdv.document_version_id = rri.document_version_id
        ORDER BY r.canonical_slug, rri.sort_key
    """
    with _readonly_connection(database) as connection:
        documents = [dict(row) for row in connection.execute(query)]
        origins = [
            dict(row)
            for row in connection.execute(
                """
                SELECT document_id, mapping_evidence_json
                FROM research_document_origin
                WHERE origin_kind = 'archive_path' AND mapping_status = 'verified'
                ORDER BY document_id, origin_id
                """
            )
        ]
    origin_paths: dict[str, set[str]] = {}
    for row in origins:
        try:
            evidence = json.loads(str(row["mapping_evidence_json"]))
        except json.JSONDecodeError as error:
            raise RevisionWorkspaceError("document origin evidence JSON is invalid") from error
        source_path = str(evidence.get("source_path", "")).replace("\\", "/")
        if source_path:
            origin_paths.setdefault(str(row["document_id"]), set()).add(source_path)
    result: dict[tuple[str, str], ActiveDocument] = {}
    for row in documents:
        document_id = str(row["document_id"])
        for source_path in sorted(origin_paths.get(document_id, ())):
            identity = (str(row["canonical_slug"]), source_path)
            value = ActiveDocument(
                research_slug=identity[0],
                research_id=str(row["research_id"]),
                document_id=document_id,
                document_slug=str(row["document_slug"]),
                source_path=source_path,
                source_sha256=str(row["content_sha256"]),
                source_bytes=int(row["bytes"]),
                sort_key=int(row["sort_key"]),
            )
            previous = result.get(identity)
            if previous is not None and previous.document_id != value.document_id:
                raise RevisionWorkspaceError(
                    f"published source path maps to multiple documents: {source_path}"
                )
            result[identity] = value
    return result


def _replace_tokens(value: str, replacements: Mapping[str, str]) -> str:
    result = value
    for token, replacement in sorted(replacements.items(), key=lambda item: -len(item[0])):
        result = result.replace(token, replacement)
    return result


def displayed_heading(
    source_title: str, source_path: str, presentation: Mapping[str, Any]
) -> str:
    path_overrides = presentation.get("heading_overrides_by_path", {})
    local = path_overrides.get(source_path, {}) if isinstance(path_overrides, dict) else {}
    global_overrides = presentation.get("heading_overrides", {})
    if not isinstance(global_overrides, dict):
        global_overrides = {}
    title = str(local.get(source_title, global_overrides.get(source_title, source_title)))
    visible = presentation.get("visible_text_overrides", {})
    if isinstance(visible, dict):
        title = _replace_tokens(title, {str(k): str(v) for k, v in visible.items()})
    tokens = presentation.get("heading_token_overrides", {})
    if isinstance(tokens, dict):
        title = _replace_tokens(title, {str(k): str(v) for k, v in tokens.items()})
    return title


def project_heading_labels(
    markdown_text: str, source_path: str, presentation: Mapping[str, Any]
) -> str:
    """只投影前端标题标签；正文、公式、表格、代码块保持完整。"""

    output: list[str] = []
    active_fence: tuple[str, int] | None = None
    for line in markdown_text.splitlines(keepends=True):
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group("fence")
            kind = marker[0]
            if active_fence is None:
                active_fence = (kind, len(marker))
            elif kind == active_fence[0] and len(marker) >= active_fence[1]:
                active_fence = None
            output.append(line)
            continue
        if active_fence is not None:
            output.append(line)
            continue
        match = ATX_HEADING_RE.match(line)
        if match is None:
            output.append(line)
            continue
        source_title = match.group("title").strip()
        projected = displayed_heading(source_title, source_path, presentation)
        eol = match.group("eol") or ""
        closing = match.group("closing") or ""
        output.append(
            f"{match.group('indent')}{match.group('marks')}{match.group('gap')}"
            f"{projected}{closing}{eol}"
        )
    # 修订工作区统一使用 UTF-8/LF；来源的原始换行字节仍由 source/slice
    # SHA-256 单独约束，不把 Windows CRLF 差异误判为研究内容修改。
    return "".join(output).replace("\r\n", "\n").replace("\r", "\n")


def first_heading(markdown_text: str) -> str | None:
    active_fence: tuple[str, int] | None = None
    for line in markdown_text.splitlines():
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group("fence")
            if active_fence is None:
                active_fence = (marker[0], len(marker))
            elif marker[0] == active_fence[0] and len(marker) >= active_fence[1]:
                active_fence = None
            continue
        if active_fence is None:
            match = ATX_HEADING_RE.match(line)
            if match:
                return match.group("title").strip()
    return None


def document_title(
    research: Mapping[str, Any], source_path: str, source_markdown: str,
    presentation: Mapping[str, Any]
) -> str:
    titles = research.get("document_titles", {})
    if isinstance(titles, dict) and source_path in titles:
        return str(titles[source_path])
    heading = first_heading(source_markdown)
    if heading:
        return displayed_heading(heading, source_path, presentation)
    return PurePosixPath(source_path).stem


def _manifest_document(
    manifest: Mapping[str, Any] | None, document: ActiveDocument
) -> dict[str, Any] | None:
    if manifest is None:
        return None
    matches = [
        item
        for item in manifest.get("documents", [])
        if isinstance(item, dict) and str(item.get("source_path")) == document.source_path
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise RevisionWorkspaceError(
            f"chapter manifest duplicates source path: {document.source_path}"
        )
    match = dict(matches[0])
    if str(match.get("source_sha256")) != document.source_sha256:
        raise RevisionWorkspaceError(
            f"chapter manifest source hash differs from active release: {document.source_path}"
        )
    return match


def _page_header(metadata: Mapping[str, Any]) -> str:
    compact = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (
        f"<!-- {COPY_MARKER}\n"
        "本文件是独立人工修订稿；修改不会自动影响 Quant Research Hub 前端。\n"
        f"{compact}\n"
        "-->\n\n"
    )


def _markdown_link(path: Path) -> str:
    return f"<{path.as_posix()}>"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _unique_relative(path: Path, seen: set[str]) -> None:
    identity = path.as_posix().casefold()
    if identity in seen:
        raise RevisionWorkspaceError(f"case-insensitive output path collision: {path}")
    seen.add(identity)


def _page_file(
    document_root: Path, ordinal: int, title: str, *, seen: set[str], staging: Path
) -> Path:
    component = numbered_component(ordinal, title, max_chars=54) + ".md"
    candidate = document_root / component
    if len(str(candidate)) > 238:
        excess = len(str(candidate)) - 238
        component = numbered_component(
            ordinal, title, max_chars=max(20, 54 - excess)
        ) + ".md"
        candidate = document_root / component
    if len(str(candidate)) > 238:
        raise RevisionWorkspaceError(f"output path remains too long: {candidate}")
    _unique_relative(candidate.relative_to(staging), seen)
    return candidate


def _research_readme(
    *, research_title: str, research: Mapping[str, Any], page_rows: Sequence[Mapping[str, Any]],
    research_root: Path
) -> str:
    orientation = research.get("orientation", {})
    lines = [
        f"# {research_title}",
        "",
        "> 本目录是当前前端研究结构的离线修订副本；修改不会自动影响前端。",
        "",
        str(research.get("summary", "")).strip(),
        "",
    ]
    if isinstance(orientation, dict):
        question = str(orientation.get("question", "")).strip()
        if question:
            lines.extend(["## 研究问题", "", question, ""])
        stages = orientation.get("stages", [])
        if isinstance(stages, list) and stages:
            lines.extend(["## 研究结构", ""])
            for stage in stages:
                if not isinstance(stage, dict):
                    continue
                lines.append(
                    f"- **{stage.get('title', '')}**：{stage.get('description', '')}"
                )
            lines.append("")
    lines.extend(["## 页面文件", ""])
    for row in page_rows:
        target = Path(str(row["workspace_relative_path"]))
        relative = Path(os.path.relpath(target, research_root.relative_to(research_root.parent)))
        lines.append(f"- [{row['page_title']}]({_markdown_link(relative)})")
    lines.append("")
    return "\n".join(lines)


def export_workspace(
    *, project_root: Path, archive_root: Path, delivery_var: Path, output_root: Path
) -> dict[str, Any]:
    validate_roots(
        project_root=project_root,
        archive_root=archive_root,
        delivery_var=delivery_var,
        output_root=output_root,
    )
    presentation_root = (
        delivery_var / "runtime_contract" / "code" / "src" / "quant_hub" / "presentation"
    ).resolve(strict=True)
    presentation_path = presentation_root / "archive_presentation.json"
    presentation = load_json(presentation_path)
    research_map = presentation.get("research")
    if not isinstance(research_map, dict) or not research_map:
        raise RevisionWorkspaceError("presentation manifest has no published research map")
    chapter_manifests = load_active_chapter_manifests(presentation_root)
    active_documents = load_active_documents(delivery_var / "db" / "archive.sqlite3")
    exported_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    staging = output_root.parent / f".{output_root.name}.building-{uuid.uuid4().hex}"
    staging_parent = staging.parent.resolve(strict=True)
    if output_root.parent.resolve(strict=True) != staging_parent:
        raise RevisionWorkspaceError("staging directory escaped output parent")
    staging.mkdir(parents=False, exist_ok=False)
    seen_paths: set[str] = set()
    pages: list[dict[str, Any]] = []
    research_indexes: list[dict[str, Any]] = []
    try:
        for research_ordinal, (research_slug, raw_research) in enumerate(
            research_map.items(), start=1
        ):
            if not isinstance(raw_research, dict):
                raise RevisionWorkspaceError(f"research presentation row is invalid: {research_slug}")
            research_title = str(raw_research.get("title", research_slug))
            research_dir = staging / numbered_component(
                research_ordinal, research_title, max_chars=38
            )
            research_dir.mkdir(parents=True)
            research_pages: list[dict[str, Any]] = []
            groups = raw_research.get("document_groups", [])
            if not isinstance(groups, list) or not groups:
                raise RevisionWorkspaceError(f"research has no document groups: {research_slug}")
            for group_ordinal, group in enumerate(groups, start=1):
                if not isinstance(group, dict):
                    raise RevisionWorkspaceError("document group row is invalid")
                group_title = str(group.get("title", "研究文档"))
                group_dir = research_dir / numbered_component(
                    group_ordinal, group_title, max_chars=32
                )
                paths = group.get("paths", [])
                if not isinstance(paths, list):
                    raise RevisionWorkspaceError("document group paths are invalid")
                for document_ordinal, raw_path in enumerate(paths, start=1):
                    source_path = str(raw_path).replace("\\", "/")
                    identity = (research_slug, source_path)
                    document = active_documents.get(identity)
                    if document is None:
                        raise RevisionWorkspaceError(
                            f"front-end document is absent from active release: {identity}"
                        )
                    source_file = archive_root / Path(source_path)
                    source_payload = source_file.read_bytes()
                    if len(source_payload) != document.source_bytes:
                        raise RevisionWorkspaceError(
                            f"source byte size differs from active release: {source_path}"
                        )
                    if sha256(source_payload) != document.source_sha256:
                        raise RevisionWorkspaceError(
                            f"source hash differs from active release: {source_path}"
                        )
                    source_markdown = source_payload.decode("utf-8")
                    title = document_title(
                        raw_research, source_path, source_markdown, presentation
                    )
                    document_dir = group_dir / numbered_component(
                        document_ordinal, title, max_chars=48
                    )
                    chapter_document = _manifest_document(
                        chapter_manifests.get(research_slug), document
                    )
                    chapters = (
                        list(chapter_document.get("chapters", []))
                        if chapter_document is not None
                        else [
                            {
                                "ordinal": 1,
                                "chapter_key": f"{document.document_slug}/complete-document",
                                "chapter_revision_id": None,
                                "display_title": title,
                                "group": group_title,
                                "absolute_start": 0,
                                "absolute_end": len(source_payload),
                                "source_slice_sha256": document.source_sha256,
                            }
                        ]
                    )
                    for chapter in chapters:
                        chapter_ordinal = int(chapter["ordinal"])
                        start = int(chapter["absolute_start"])
                        end = int(chapter["absolute_end"])
                        if not 0 <= start < end <= len(source_payload):
                            raise RevisionWorkspaceError(
                                f"chapter byte range is invalid: {source_path} {start}:{end}"
                            )
                        slice_payload = source_payload[start:end]
                        slice_sha = sha256(slice_payload)
                        if slice_sha != str(chapter["source_slice_sha256"]):
                            raise RevisionWorkspaceError(
                                f"chapter slice hash mismatch: {source_path} {chapter['chapter_key']}"
                            )
                        page_title = str(chapter["display_title"])
                        route_slug = str(chapter["chapter_key"]).split("/", 1)[-1]
                        frontend_url = (
                            f"/research/{document.research_id}/documents/{document.document_id}"
                            f"/chapters/{route_slug}"
                            if chapter_document is not None
                            else f"/research/{document.research_id}/documents/{document.document_id}"
                        )
                        page_id = "rpage_" + hashlib.sha256(
                            (
                                f"{research_slug}\0{document.document_id}\0"
                                f"{chapter['chapter_key']}\0{slice_sha}"
                            ).encode("utf-8")
                        ).hexdigest()[:32]
                        projected = project_heading_labels(
                            slice_payload.decode("utf-8"), source_path, presentation
                        )
                        page_path = _page_file(
                            document_dir,
                            chapter_ordinal,
                            page_title,
                            seen=seen_paths,
                            staging=staging,
                        )
                        relative_path = page_path.relative_to(staging)
                        header_metadata = {
                            "page_id": page_id,
                            "page_title": page_title,
                            "frontend_url": frontend_url,
                            "sync_policy": "manual_review_only",
                        }
                        _write(page_path, _page_header(header_metadata) + projected)
                        row = {
                            "page_id": page_id,
                            "page_title": page_title,
                            "research_slug": research_slug,
                            "research_title": research_title,
                            "group_key": str(group.get("key", "")),
                            "group_title": group_title,
                            "document_id": document.document_id,
                            "document_title": title,
                            "document_slug": document.document_slug,
                            "chapter_key": str(chapter["chapter_key"]),
                            "chapter_revision_id": chapter.get("chapter_revision_id"),
                            "chapter_ordinal": chapter_ordinal,
                            "source_path": source_path,
                            "source_sha256": document.source_sha256,
                            "source_absolute_start": start,
                            "source_absolute_end": end,
                            "source_slice_sha256": slice_sha,
                            "exported_markdown_sha256": sha256(projected.encode("utf-8")),
                            "workspace_relative_path": relative_path.as_posix(),
                            "frontend_url": frontend_url,
                            "runtime_binding": False,
                            "sync_policy": "manual_review_only",
                            "projection": "source_markdown_slice_with_frontend_heading_titles",
                        }
                        pages.append(row)
                        research_pages.append(row)
            readme_path = research_dir / "README.md"
            _unique_relative(readme_path.relative_to(staging), seen_paths)
            _write(
                readme_path,
                _research_readme(
                    research_title=research_title,
                    research=raw_research,
                    page_rows=research_pages,
                    research_root=research_dir,
                ),
            )
            research_indexes.append(
                {
                    "ordinal": research_ordinal,
                    "research_slug": research_slug,
                    "research_title": research_title,
                    "page_count": len(research_pages),
                    "directory": research_dir.relative_to(staging).as_posix(),
                }
            )

        manifest = {
            "schema_version": MANIFEST_SCHEMA,
            "status": "READY_FOR_MANUAL_RESEARCH_REVISION",
            "exported_at": exported_at,
            "project_root": str(project_root.resolve(strict=True)),
            "archive_root": str(archive_root.resolve(strict=True)),
            "delivery_var": str(delivery_var.resolve(strict=True)),
            "presentation_manifest": {
                "path": str(presentation_path),
                "sha256": sha256(presentation_path.read_bytes()),
            },
            "runtime_binding": False,
            "sync_policy": "manual_review_only",
            "research_count": len(research_indexes),
            "page_count": len(pages),
            "research": research_indexes,
            "pages": pages,
        }
        manifest_material = dict(manifest)
        manifest["manifest_content_sha256"] = sha256(
            canonical_json(manifest_material).encode("utf-8")
        )
        _write(staging / "_导出清单.json", canonical_json(manifest))
        readme = [
            "# Quant Research Hub 研究修订工作区",
            "",
            "> 这里是一份与当前前端页面结构对应的离线 Markdown 修订副本。",
            "> 修改本目录中的任何文件都不会自动改变前端、数据库或 Archive 原稿。",
            "",
            "## 使用方法",
            "",
            "1. 进入对应研究专题、文档和章节，直接修改 Markdown 页面文件。",
            "2. 不要删除页面顶部的隐藏身份注释，也不要修改 `_导出清单.json`。",
            "3. 修改完成后把文件路径交给 Codex；由 Codex 比较基线、审阅研究变更，再显式修改前端展示层。",
            "4. 原始 `reference/archive`、当前前端和本工作区三者相互独立；这里不承担自动同步。",
            "",
            "可随时运行以下只读命令列出已经修改的页面：",
            "",
            "```powershell",
            "D:\\conda\\python.exe quant_hub\\tools\\report_research_revision_changes.py",
            "```",
            "",
            "## 导出范围",
            "",
            f"- 已发布研究专题：{len(research_indexes)}",
            f"- 前端页面 Markdown：{len(pages)}",
            f"- 冻结交付：`{delivery_var.name}`",
            "",
            "## 专题目录",
            "",
        ]
        for row in research_indexes:
            readme.append(
                f"- [{row['research_title']}]"
                f"(<{row['directory']}/README.md>)（{row['page_count']} 页）"
            )
        readme.append("")
        _write(staging / "README.md", "\n".join(readme))
        os.replace(staging, output_root)
    except Exception:
        resolved = staging.resolve(strict=False)
        if resolved.parent == staging_parent and resolved.name.startswith(
            f".{output_root.name}.building-"
        ):
            shutil.rmtree(resolved, ignore_errors=True)
        raise
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--project-root", type=Path, default=WORKSPACE_ROOT)
    result.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    result.add_argument("--delivery-var", type=Path, required=True)
    result.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return result


def main(argv: Sequence[str] | None = None) -> None:
    args = parser().parse_args(argv)
    try:
        manifest = export_workspace(
            project_root=args.project_root,
            archive_root=args.archive_root,
            delivery_var=args.delivery_var,
            output_root=args.output_root,
        )
    except RevisionWorkspaceError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    print(
        canonical_json(
            {
                "status": "PASS",
                "output_root": str(args.output_root.resolve(strict=True)),
                "research_count": manifest["research_count"],
                "page_count": manifest["page_count"],
                "manifest_content_sha256": manifest["manifest_content_sha256"],
            }
        ),
        end="",
    )


if __name__ == "__main__":
    main()
