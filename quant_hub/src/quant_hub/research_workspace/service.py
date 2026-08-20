from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import threading
from typing import Any, Literal

from quant_hub.archive.contracts import ActorInput
from quant_hub.archive.database import archive_connection
from quant_hub.config import (
    ConfigurationError,
    Settings,
    ensure_no_reparse_components,
    stat_is_reparse_point,
)
from quant_hub.ids import new_public_id, sha256_hex, stable_sha256
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.workflow import canonical_json
from quant_hub.research_workspace.database import research_workspace_connection


LifecycleStatus = Literal[
    "todo", "in_progress", "review", "completed", "archived", "cancelled"
]
NodeKind = Literal["system", "project", "topic", "subtopic", "document"]

_SORT_PREFIX = re.compile(r"^(?P<order>\d{1,4})[_\-. ]+(?P<title>.+)$")
_HEADING = re.compile(r"^\s{0,3}#\s+(?P<title>.+?)\s*#*\s*$")
_SECOND_LEVEL_HEADING = re.compile(
    r"^\s{0,3}##\s+(?P<title>.+?)\s*#*\s*$"
)
_FENCE = re.compile(r"^\s{0,3}(?P<marker>`{3,}|~{3,})")
_SCANNER_SCHEMA_VERSION = "research-workspace-v2"
_PROJECT_CREATE_LOCK = threading.RLock()
_PROJECT_TITLE_PREFIX = re.compile(
    r"^\s*Q\d+\s*[｜|:：—–_-]\s*",
    re.IGNORECASE,
)
_WINDOWS_UNSAFE_COMPONENT = re.compile(r"[\x00-\x1f<>:\"/\\|?*]+")
_WINDOWS_RESERVED_COMPONENTS = {
    "con", "prn", "aux", "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_PROJECT_TITLES = {
    "因子质量、稳健性与可交易性评估": (
        "Q1｜如何评价一个好的产品：因子质量、稳健性与可交易性评估"
    ),
    "低信噪比选股模型训练体系": (
        "Q2｜如何造一个好的工厂：低信噪比选股模型训练体系"
    ),
    "模型训练可靠性与过拟合诊断": (
        "Q3｜如何评价一个好的工厂：模型训练可靠性与过拟合诊断"
    ),
    "量化模型部署监控与漂移诊断": (
        "Q4｜实操与部署后监测：量化模型部署监控与漂移诊断"
    ),
    "低信噪比因子序列表征": "Q5｜低信噪比因子序列表征",
    "量化研究失效模式诊断": "Q6｜量化研究失效模式诊断",
    "低信噪比模型验证实验体系": "Q7｜低信噪比模型验证实验体系",
}


class WorkspaceError(RuntimeError):
    pass


class WorkspaceNotFound(WorkspaceError):
    pass


class WorkspaceIdempotencyConflict(WorkspaceError):
    pass


@dataclass(frozen=True, slots=True)
class WorkspaceCommandOutcome:
    ok: bool
    status: int
    data: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class _SourceEntry:
    relative_path: str
    path_key: str
    parent_path: str | None
    entry_kind: Literal["virtual", "directory", "markdown"]
    node_kind: NodeKind
    default_title: str
    description: str | None
    research_question: str | None
    research_content: str | None
    sort_key: int
    sha256: str | None
    bytes: int | None
    mtime_ns: int | None
    research_id: str | None
    document_id: str | None
    published_page_url: str | None
    initial_status: LifecycleStatus


def _actor_name(actor: ActorInput) -> str:
    if actor.actor_kind == "zhang_zhengze":
        return "张正泽"
    if actor.actor_kind == "song_dingkun":
        return "宋定坤"
    assert actor.display_name is not None
    return actor.display_name.strip()


def _display_component(value: str) -> tuple[int, str]:
    match = _SORT_PREFIX.match(value)
    if match is None:
        return 100_000, value.strip()
    return int(match.group("order")), match.group("title").strip()


def _first_heading(text: str) -> str | None:
    active_fence: tuple[str, int] | None = None
    for line in text.splitlines():
        fence = _FENCE.match(line)
        if fence:
            marker = fence.group("marker")
            if active_fence is None:
                active_fence = (marker[0], len(marker))
            elif marker[0] == active_fence[0] and len(marker) >= active_fence[1]:
                active_fence = None
            continue
        if active_fence is None:
            heading = _HEADING.match(line)
            if heading:
                return heading.group("title").strip()
    return None


def _readme_description(text: str) -> str | None:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    paragraphs: list[str] = []
    current: list[str] = []
    fenced = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced or line.startswith("#"):
            continue
        if not line:
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        if line.startswith(("-", "*", ">", "|")):
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        current.append(line)
    if current:
        paragraphs.append(" ".join(current))
    for paragraph in paragraphs:
        normalized = paragraph.strip()
        if normalized and "修改不会自动" not in normalized and len(normalized) >= 12:
            return normalized[:8_000]
    return None


def _plain_readme_section(lines: list[str], *, limit: int) -> str | None:
    rendered: list[str] = []
    fenced = False
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced:
            rendered.append(line)
            continue
        if not stripped:
            if rendered and rendered[-1]:
                rendered.append("")
            continue
        stripped = re.sub(r"^\s*[-*+]\s+", "• ", stripped)
        stripped = stripped.replace("**", "").replace("__", "")
        rendered.append(stripped)
    while rendered and not rendered[-1]:
        rendered.pop()
    value = "\n".join(rendered).strip()
    return value[:limit] if value else None


def _readme_research_fields(text: str) -> tuple[str | None, str | None]:
    """Extract editable project semantics without treating README as live UI state."""

    sections: dict[str, list[str]] = {}
    current: str | None = None
    fenced = False
    for raw in re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL).splitlines():
        fence = _FENCE.match(raw)
        if fence:
            fenced = not fenced
            if current is not None:
                sections.setdefault(current, []).append(raw)
            continue
        if not fenced:
            heading = _SECOND_LEVEL_HEADING.match(raw)
            if heading:
                current = heading.group("title").strip()
                sections.setdefault(current, [])
                continue
        if current is not None:
            sections.setdefault(current, []).append(raw)
    return (
        _plain_readme_section(sections.get("研究问题", []), limit=8_000),
        _plain_readme_section(sections.get("研究结构", []), limit=20_000),
    )


def _project_title(order: int, fallback: str) -> str:
    if fallback in _PROJECT_TITLES:
        return _PROJECT_TITLES[fallback]
    if order < 100_000:
        return f"Q{order}｜{fallback}"
    return fallback


def _manual_project_title(value: str) -> str:
    """Return the researcher-entered title without a duplicated Q prefix."""

    title = _PROJECT_TITLE_PREFIX.sub("", value).strip()
    if not title or any(character in title for character in "\r\n\t"):
        raise ValueError("研究专项标题必须是单行有效文本。")
    return title


def _project_directory_component(title: str) -> str:
    component = _WINDOWS_UNSAFE_COMPONENT.sub(" ", title)
    component = re.sub(r"\s+", " ", component).strip(" .")
    component = component[:96].rstrip(" .")
    if not component:
        raise ValueError("研究专项标题无法转换为安全目录名。")
    if component.casefold().split(".", 1)[0] in _WINDOWS_RESERVED_COMPONENTS:
        component = f"研究_{component}"
    return component


def _project_readme(
    display_title: str,
    description: str | None,
    research_question: str | None,
    research_content: str | None,
) -> str:
    blocks = [f"# {display_title}"]
    if description:
        blocks.append(description)
    blocks.extend(
        [
            "## 研究问题",
            research_question or "",
            "## 研究结构",
            research_content or "",
        ]
    )
    return "\n\n".join(blocks).rstrip() + "\n"


def _path_key(relative_path: str) -> str:
    return relative_path.replace("\\", "/").casefold()


def _node_data(row: sqlite3.Row) -> dict[str, Any]:
    title = row["title_override"] or row["default_title"]
    description = row["description_override"] or row["default_description"]
    research_question = (
        row["research_question_override"] or row["default_research_question"]
    )
    research_content = (
        row["research_content_override"] or row["default_research_content"]
    )
    return {
        "node_id": str(row["node_id"]),
        "parent_node_id": (
            str(row["parent_node_id"]) if row["parent_node_id"] is not None else None
        ),
        "node_kind": str(row["node_kind"]),
        "source_entry_kind": str(row["source_entry_kind"]),
        "source_relative_path": str(row["source_relative_path"]),
        "source_state": str(row["source_state"]),
        "display_title": str(title),
        "default_title": str(row["default_title"]),
        "title_override": (
            str(row["title_override"]) if row["title_override"] is not None else None
        ),
        "description": (
            str(description) if description is not None else None
        ),
        "default_description": (
            str(row["default_description"])
            if row["default_description"] is not None
            else None
        ),
        "description_override": (
            str(row["description_override"])
            if row["description_override"] is not None
            else None
        ),
        "research_question": (
            str(research_question) if research_question is not None else None
        ),
        "default_research_question": (
            str(row["default_research_question"])
            if row["default_research_question"] is not None
            else None
        ),
        "research_question_override": (
            str(row["research_question_override"])
            if row["research_question_override"] is not None
            else None
        ),
        "research_content": (
            str(research_content) if research_content is not None else None
        ),
        "default_research_content": (
            str(row["default_research_content"])
            if row["default_research_content"] is not None
            else None
        ),
        "research_content_override": (
            str(row["research_content_override"])
            if row["research_content_override"] is not None
            else None
        ),
        "lifecycle_status": str(row["lifecycle_status"]),
        "status_note": (
            str(row["status_note"]) if row["status_note"] is not None else None
        ),
        "sort_key": int(row["sort_key"]),
        "research_id": (
            str(row["research_id"]) if row["research_id"] is not None else None
        ),
        "document_id": (
            str(row["document_id"]) if row["document_id"] is not None else None
        ),
        "source_sha256": (
            str(row["source_sha256"]) if row["source_sha256"] is not None else None
        ),
        "source_bytes": (
            int(row["source_bytes"]) if row["source_bytes"] is not None else None
        ),
        "source_mtime_ns": (
            int(row["source_mtime_ns"]) if row["source_mtime_ns"] is not None else None
        ),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "missing_at": (
            str(row["missing_at"]) if row["missing_at"] is not None else None
        ),
        "revision": int(row["revision"]),
        "page_url": (
            str(row["published_page_url"])
            if row["published_page_url"] is not None
            else None
        ),
    }


class ResearchWorkspace:
    """Synchronize and manage the writable research tree without publishing it."""

    def __init__(
        self,
        settings: Settings,
        *,
        database_path: Path | None = None,
    ):
        self.settings = settings
        self.root = settings.research_workspace_root.absolute()
        self.database_path = (
            database_path.resolve()
            if database_path is not None
            else settings.research_workspace_database_path
        )

    def _connection(self):
        return research_workspace_connection(
            self.settings,
            database_path=self.database_path,
        )

    @staticmethod
    def _actor_id(connection: sqlite3.Connection, actor: ActorInput) -> str:
        name = _actor_name(actor)
        row = connection.execute(
            "SELECT actor_id FROM actor WHERE actor_kind=? AND display_name=?",
            (actor.actor_kind, name),
        ).fetchone()
        if row is not None:
            return str(row["actor_id"])
        actor_id = new_public_id("act")
        connection.execute(
            "INSERT INTO actor(actor_id,actor_kind,display_name,created_at) VALUES(?,?,?,?)",
            (actor_id, actor.actor_kind, name, utc_now()),
        )
        return actor_id

    @staticmethod
    def _payload_hash(command: str, payload: dict[str, Any]) -> str:
        return stable_sha256("research-workspace-command/v1", command, canonical_json(payload))

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        *,
        command: str,
        idempotency_key: str,
        payload_hash: str,
    ) -> WorkspaceCommandOutcome | None:
        row = connection.execute(
            """
            SELECT command_name,payload_hash,outcome_json,http_status
            FROM research_workspace_command_receipt WHERE idempotency_key=?
            """,
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        if (str(row["command_name"]), str(row["payload_hash"])) != (
            command,
            payload_hash,
        ):
            raise WorkspaceIdempotencyConflict(
                "idempotency key is bound to another workspace command"
            )
        payload = json.loads(str(row["outcome_json"]))
        if "data" in payload:
            return WorkspaceCommandOutcome(
                True, int(row["http_status"]), data=dict(payload["data"]), replayed=True
            )
        error = payload["error"]
        return WorkspaceCommandOutcome(
            False,
            int(row["http_status"]),
            error_code=str(error["code"]),
            error_message=str(error["message"]),
            replayed=True,
        )

    @staticmethod
    def _record(
        connection: sqlite3.Connection,
        *,
        command: str,
        idempotency_key: str,
        payload_hash: str,
        outcome: WorkspaceCommandOutcome,
    ) -> WorkspaceCommandOutcome:
        result = (
            {"data": outcome.data or {}}
            if outcome.ok
            else {
                "error": {
                    "code": outcome.error_code or "workspace_command_rejected",
                    "message": outcome.error_message or "研究工作区命令未被接受。",
                }
            }
        )
        connection.execute(
            """
            INSERT INTO research_workspace_command_receipt(
                receipt_id,idempotency_key,command_name,payload_hash,
                outcome_json,http_status,created_at
            ) VALUES(?,?,?,?,?,?,?)
            """,
            (
                new_public_id("wrcpt"),
                idempotency_key,
                command,
                payload_hash,
                canonical_json(result),
                outcome.status,
                utc_now(),
            ),
        )
        return outcome

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        *,
        node_id: str,
        event_kind: str,
        prior_revision: int | None,
        new_revision: int,
        sync_run_id: str | None = None,
        actor_id: str | None = None,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
        note: str | None = None,
        occurred_at: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO research_workspace_event(
                event_id,sync_run_id,node_id,event_kind,actor_id,prior_revision,
                new_revision,old_value_json,new_value_json,note,occurred_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                new_public_id("wevt"),
                sync_run_id,
                node_id,
                event_kind,
                actor_id,
                prior_revision,
                new_revision,
                canonical_json(old_value) if old_value is not None else None,
                canonical_json(new_value) if new_value is not None else None,
                note,
                occurred_at or utc_now(),
            ),
        )

    def _validate_root(self) -> Path:
        ensure_no_reparse_components(self.root)
        if not self.root.is_dir():
            raise ConfigurationError(f"research workspace root is missing: {self.root}")
        root = self.root.resolve(strict=True)
        reference = (self.settings.project_root / "reference").resolve(strict=True)
        try:
            root.relative_to(reference)
        except ValueError:
            pass
        else:
            raise ConfigurationError("research workspace must not be inside reference/**")
        info = root.lstat()
        if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
            raise ConfigurationError("research workspace root must be a real directory")
        return root

    def _quick_signature(self) -> str:
        """Hash path/type/size/mtime without following reparse points."""

        root = self._validate_root()
        material: list[str] = [f"scanner\0{_SCANNER_SCHEMA_VERSION}"]
        for current, directory_names, file_names in os.walk(root, followlinks=False):
            current_path = Path(current)
            safe_directories: list[str] = []
            for name in sorted(directory_names, key=lambda value: value.casefold()):
                candidate = current_path / name
                info = candidate.lstat()
                if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                    continue
                safe_directories.append(name)
                material.append(
                    f"d\0{candidate.relative_to(root).as_posix()}\0{info.st_mtime_ns}"
                )
            directory_names[:] = safe_directories
            for name in sorted(file_names, key=lambda value: value.casefold()):
                candidate = current_path / name
                info = candidate.lstat()
                if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode):
                    continue
                if candidate.suffix.casefold() not in {".md", ".markdown"}:
                    continue
                material.append(
                    f"f\0{candidate.relative_to(root).as_posix()}\0"
                    f"{info.st_size}\0{info.st_mtime_ns}"
                )
        return sha256_hex("\n".join(material).encode("utf-8"))

    def _manifest_bindings(
        self, root: Path
    ) -> tuple[dict[str, str], dict[str, tuple[str, str | None, str]]]:
        path = root / "_导出清单.json"
        if not path.is_file():
            return {}, {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}, {}
        projects: dict[str, str] = {}
        documents: dict[str, tuple[str, str, str]] = {}
        with archive_connection(self.settings) as connection:
            research_by_slug = {
                str(row["canonical_slug"]): str(row["research_id"])
                for row in connection.execute(
                    "SELECT canonical_slug,research_id FROM research"
                )
            }
            document_research = {
                str(row["document_id"]): str(row["research_id"])
                for row in connection.execute(
                    "SELECT document_id,research_id FROM research_document"
                )
            }
        for item in payload.get("research", []):
            if not isinstance(item, dict):
                continue
            directory = str(item.get("directory", "")).replace("\\", "/")
            slug = str(item.get("research_slug", ""))
            research_id = research_by_slug.get(slug)
            if directory and research_id is not None:
                projects[_path_key(directory)] = research_id
        for item in payload.get("pages", []):
            if not isinstance(item, dict):
                continue
            relative = str(item.get("workspace_relative_path", "")).replace("\\", "/")
            research_slug = str(item.get("research_slug", ""))
            document_id = str(item.get("document_id", ""))
            research_id = research_by_slug.get(research_slug)
            document_research_id = document_research.get(document_id)
            if (
                relative
                and research_id is not None
                and document_research_id is not None
                and research_id == document_research_id
            ):
                page_url = str(item.get("frontend_url") or "")
                if not page_url.startswith("/research/"):
                    page_url = (
                        f"/research/{research_id}/documents/{document_id}"
                    )
                documents[_path_key(relative)] = (
                    research_id,
                    document_id,
                    page_url,
                )
        # Reviewed supplements are published reader pages too, but they are
        # intentionally outside the immutable Archive document database.  Bind
        # their exact workspace paths here so every managed Markdown leaf—and
        # therefore every parent chapter—has an honest正文 target.
        from quant_hub.presentation.supplements import SupplementalResearchDocuments

        for relative, binding in SupplementalResearchDocuments.default().workspace_page_bindings(
            research_by_slug
        ).items():
            existing = documents.get(relative)
            if existing is not None and existing != binding:
                raise WorkspaceError(
                    f"workspace path has conflicting reader pages: {relative}"
                )
            documents[relative] = binding
        return projects, documents

    def _scan(self) -> list[_SourceEntry]:
        root = self._validate_root()
        project_bindings, document_bindings = self._manifest_bindings(root)
        readmes: dict[str, tuple[str | None, str | None, str | None]] = {}
        raw_files: dict[str, tuple[bytes, os.stat_result]] = {}
        directories: list[str] = ["."]

        for current, directory_names, file_names in os.walk(root, followlinks=False):
            current_path = Path(current)
            current_relative = (
                "." if current_path == root else current_path.relative_to(root).as_posix()
            )
            safe_directories: list[str] = []
            for name in sorted(directory_names, key=lambda value: value.casefold()):
                candidate = current_path / name
                info = candidate.lstat()
                if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                    continue
                safe_directories.append(name)
                directories.append(candidate.relative_to(root).as_posix())
            directory_names[:] = safe_directories

            for name in sorted(file_names, key=lambda value: value.casefold()):
                candidate = current_path / name
                info = candidate.lstat()
                if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode):
                    continue
                if candidate.suffix.casefold() not in {".md", ".markdown"}:
                    continue
                payload = candidate.read_bytes()
                after = candidate.lstat()
                if (
                    stat_is_reparse_point(after)
                    or not stat.S_ISREG(after.st_mode)
                    or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or len(payload) != after.st_size
                ):
                    raise WorkspaceError(f"research workspace file changed during scan: {candidate}")
                try:
                    text = payload.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise WorkspaceError(f"research workspace Markdown is not UTF-8: {candidate}") from error
                relative = candidate.relative_to(root).as_posix()
                if name.casefold() == "readme.md":
                    question, content = _readme_research_fields(text)
                    readmes[current_relative] = (
                        _readme_description(text),
                        question,
                        content,
                    )
                else:
                    raw_files[relative] = (payload, info)

        descendant_material: dict[str, list[str]] = {item: [] for item in directories}
        for relative, (payload, _info) in raw_files.items():
            digest = sha256_hex(payload)
            pure = PurePosixPath(relative)
            for directory in directories:
                if directory == ".":
                    subpath = relative
                else:
                    try:
                        subpath = pure.relative_to(PurePosixPath(directory)).as_posix()
                    except ValueError:
                        continue
                descendant_material[directory].append(f"{subpath}\0{digest}")

        project_status_by_component: dict[str, LifecycleStatus] = {
            path_key: "completed" for path_key in project_bindings
        }

        entries: list[_SourceEntry] = [
            _SourceEntry(
                relative_path=".",
                path_key=".",
                parent_path=None,
                entry_kind="virtual",
                node_kind="system",
                default_title="量化研究知识中枢",
                description=readmes.get(".", (None, None, None))[0],
                research_question=None,
                research_content=None,
                sort_key=0,
                sha256=None,
                bytes=None,
                mtime_ns=None,
                research_id=None,
                document_id=None,
                published_page_url=None,
                initial_status="in_progress",
            )
        ]
        for relative in sorted(
            (item for item in directories if item != "."),
            key=lambda value: (len(PurePosixPath(value).parts), _path_key(value)),
        ):
            pure = PurePosixPath(relative)
            depth = len(pure.parts)
            order, title = _display_component(pure.name)
            research_id = project_bindings.get(_path_key(relative))
            top_key = _path_key(pure.parts[0])
            status = project_status_by_component.get(top_key, "todo")
            readme = readmes.get(relative, (None, None, None))
            if depth == 1:
                title = _project_title(order, title)
            material = sorted(descendant_material.get(relative, []))
            directory_sha = (
                sha256_hex("\n".join(material).encode("utf-8")) if material else None
            )
            entries.append(
                _SourceEntry(
                    relative_path=relative,
                    path_key=_path_key(relative),
                    parent_path=(
                        "." if len(pure.parts) == 1 else pure.parent.as_posix()
                    ),
                    entry_kind="directory",
                    node_kind=(
                        "project" if depth == 1 else "topic" if depth == 2 else "subtopic"
                    ),
                    default_title=title,
                    description=readme[0],
                    research_question=readme[1] if depth == 1 else None,
                    research_content=readme[2] if depth == 1 else None,
                    sort_key=order,
                    sha256=directory_sha,
                    bytes=None,
                    mtime_ns=None,
                    research_id=research_id,
                    document_id=None,
                    published_page_url=(
                        f"/research/{research_id}" if research_id is not None else None
                    ),
                    initial_status=status,
                )
            )
        for relative in sorted(raw_files, key=_path_key):
            payload, info = raw_files[relative]
            pure = PurePosixPath(relative)
            order, fallback = _display_component(pure.stem)
            heading = _first_heading(payload.decode("utf-8"))
            research_id, document_id, page_url = document_bindings.get(
                _path_key(relative), (None, None, None)
            )
            top_key = _path_key(pure.parts[0])
            entries.append(
                _SourceEntry(
                    relative_path=relative,
                    path_key=_path_key(relative),
                    parent_path=pure.parent.as_posix(),
                    entry_kind="markdown",
                    node_kind="document",
                    default_title=heading or fallback,
                    description=None,
                    research_question=None,
                    research_content=None,
                    sort_key=order,
                    sha256=sha256_hex(payload),
                    bytes=len(payload),
                    mtime_ns=int(info.st_mtime_ns),
                    research_id=research_id,
                    document_id=document_id,
                    published_page_url=page_url,
                    initial_status=project_status_by_component.get(top_key, "todo"),
                )
            )
        return entries

    def sync(self) -> dict[str, Any]:
        root = self._validate_root()
        source_signature = self._quick_signature()
        started_at = utc_now()
        sync_run_id = new_public_id("wsync")
        counters = {
            "discovered_count": 0,
            "created_count": 0,
            "updated_count": 0,
            "moved_count": 0,
            "missing_count": 0,
            "restored_count": 0,
        }
        with self._connection() as connection, immediate_transaction(connection):
            connection.execute(
                """
                INSERT INTO research_workspace_sync_run(
                    sync_run_id,workspace_root,source_signature,started_at,
                    completed_at,status
                ) VALUES(?,?,?,?,NULL,'running')
                """,
                (sync_run_id, str(root), source_signature, started_at),
            )
            entries = self._scan()
            if self._quick_signature() != source_signature:
                raise WorkspaceError("research workspace changed during synchronization")
            counters["discovered_count"] = len(entries)
            current_keys = {entry.path_key for entry in entries}
            existing_rows = connection.execute(
                "SELECT * FROM research_workspace_node ORDER BY source_path_key"
            ).fetchall()
            by_path = {str(row["source_path_key"]): row for row in existing_rows}
            unmatched = {
                str(row["node_id"]): row
                for row in existing_rows
                if str(row["source_path_key"]) not in current_keys
            }
            node_by_path: dict[str, str] = {}
            claimed_nodes: set[str] = set()

            for entry in entries:
                now = utc_now()
                row = by_path.get(entry.path_key)
                moved = False
                if row is None and entry.sha256 is not None:
                    candidates = [
                        candidate
                        for candidate in unmatched.values()
                        if str(candidate["node_id"]) not in claimed_nodes
                        and str(candidate["source_entry_kind"]) == entry.entry_kind
                        and candidate["source_sha256"] == entry.sha256
                    ]
                    if len(candidates) == 1:
                        row = candidates[0]
                        moved = True
                parent_id = (
                    node_by_path.get(_path_key(entry.parent_path))
                    if entry.parent_path is not None
                    else None
                )
                if entry.parent_path is not None and parent_id is None:
                    raise WorkspaceError(
                        f"research workspace parent was not synchronized: {entry.parent_path}"
                    )
                if row is None:
                    node_id = new_public_id("rnode")
                    connection.execute(
                        """
                        INSERT INTO research_workspace_node(
                            node_id,parent_node_id,node_kind,source_entry_kind,
                            source_relative_path,source_path_key,source_sha256,
                            source_bytes,source_mtime_ns,source_state,default_title,
                            title_override,default_description,description_override,
                            default_research_question,research_question_override,
                            default_research_content,research_content_override,
                            lifecycle_status,status_note,
                            sort_key,research_id,document_id,published_page_url,
                            created_at,updated_at,
                            missing_at,revision
                        ) VALUES(
                            ?,?,?,?,?,?,?,?,?,'present',?,NULL,?,NULL,
                            ?,NULL,?,NULL,?,NULL,?,?,?,?,?,?,NULL,1
                        )
                        """,
                        (
                            node_id,
                            parent_id,
                            entry.node_kind,
                            entry.entry_kind,
                            entry.relative_path,
                            entry.path_key,
                            entry.sha256,
                            entry.bytes,
                            entry.mtime_ns,
                            entry.default_title,
                            entry.description,
                            entry.research_question,
                            entry.research_content,
                            entry.initial_status,
                            entry.sort_key,
                            entry.research_id,
                            entry.document_id,
                            entry.published_page_url,
                            now,
                            now,
                        ),
                    )
                    self._event(
                        connection,
                        sync_run_id=sync_run_id,
                        node_id=node_id,
                        event_kind="discovered",
                        prior_revision=None,
                        new_revision=1,
                        new_value={
                            "source_relative_path": entry.relative_path,
                            "lifecycle_status": entry.initial_status,
                        },
                        occurred_at=now,
                    )
                    counters["created_count"] += 1
                    revision = 1
                else:
                    node_id = str(row["node_id"])
                    claimed_nodes.add(node_id)
                    old_revision = int(row["revision"])
                    restored = str(row["source_state"]) == "missing"
                    content_changed = (
                        row["source_sha256"] != entry.sha256
                        or row["source_bytes"] != entry.bytes
                    )
                    changed = (
                        moved
                        or restored
                        or str(row["parent_node_id"] or "") != str(parent_id or "")
                        or str(row["node_kind"]) != entry.node_kind
                        or str(row["source_entry_kind"]) != entry.entry_kind
                        or str(row["source_relative_path"]) != entry.relative_path
                        or str(row["default_title"]) != entry.default_title
                        or row["default_description"] != entry.description
                        or row["default_research_question"] != entry.research_question
                        or row["default_research_content"] != entry.research_content
                        or row["source_sha256"] != entry.sha256
                        or row["source_bytes"] != entry.bytes
                        or row["source_mtime_ns"] != entry.mtime_ns
                        or row["research_id"] != entry.research_id
                        or row["document_id"] != entry.document_id
                        or row["published_page_url"] != entry.published_page_url
                        or int(row["sort_key"]) != entry.sort_key
                    )
                    revision = old_revision
                    if changed:
                        revision += 1
                        connection.execute(
                            """
                            UPDATE research_workspace_node SET
                                parent_node_id=?,node_kind=?,source_entry_kind=?,
                                source_relative_path=?,source_path_key=?,source_sha256=?,
                                source_bytes=?,source_mtime_ns=?,source_state='present',
                                default_title=?,default_description=?,
                                default_research_question=?,default_research_content=?,
                                sort_key=?,research_id=COALESCE(?,research_id),
                                document_id=COALESCE(?,document_id),
                                published_page_url=COALESCE(?,published_page_url),
                                updated_at=?,
                                missing_at=NULL,revision=?
                            WHERE node_id=?
                            """,
                            (
                                parent_id,
                                entry.node_kind,
                                entry.entry_kind,
                                entry.relative_path,
                                entry.path_key,
                                entry.sha256,
                                entry.bytes,
                                entry.mtime_ns,
                                entry.default_title,
                                entry.description,
                                entry.research_question,
                                entry.research_content,
                                entry.sort_key,
                                entry.research_id,
                                entry.document_id,
                                entry.published_page_url,
                                now,
                                revision,
                                node_id,
                            ),
                        )
                        event_kind = (
                            "moved"
                            if moved
                            else "restored"
                            if restored
                            else "content_updated"
                            if content_changed
                            else "metadata_updated"
                        )
                        self._event(
                            connection,
                            sync_run_id=sync_run_id,
                            node_id=node_id,
                            event_kind=event_kind,
                            prior_revision=old_revision,
                            new_revision=revision,
                            old_value={
                                "source_relative_path": str(row["source_relative_path"]),
                                "source_sha256": row["source_sha256"],
                            },
                            new_value={
                                "source_relative_path": entry.relative_path,
                                "source_sha256": entry.sha256,
                            },
                            occurred_at=now,
                        )
                        counters["updated_count"] += 1
                        counters["moved_count"] += int(moved)
                        counters["restored_count"] += int(restored)
                node_by_path[entry.path_key] = node_id
                connection.execute(
                    """
                    INSERT INTO research_workspace_observation(
                        observation_id,sync_run_id,node_id,source_relative_path,
                        source_sha256,source_bytes,source_mtime_ns,observed_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        new_public_id("wobs"),
                        sync_run_id,
                        node_id,
                        entry.relative_path,
                        entry.sha256,
                        entry.bytes,
                        entry.mtime_ns,
                        now,
                    ),
                )

            missing_rows = [
                row
                for row in existing_rows
                if str(row["node_id"]) not in claimed_nodes
                and str(row["source_path_key"]) not in current_keys
                and str(row["source_state"]) == "present"
            ]
            missing_rows.sort(
                key=lambda row: len(PurePosixPath(str(row["source_relative_path"])).parts),
                reverse=True,
            )
            for row in missing_rows:
                now = utc_now()
                old_revision = int(row["revision"])
                next_revision = old_revision + 1
                connection.execute(
                    """
                    UPDATE research_workspace_node
                    SET source_state='missing',lifecycle_status='archived',
                        missing_at=?,updated_at=?,revision=?
                    WHERE node_id=?
                    """,
                    (now, now, next_revision, row["node_id"]),
                )
                self._event(
                    connection,
                    sync_run_id=sync_run_id,
                    node_id=str(row["node_id"]),
                    event_kind="missing",
                    prior_revision=old_revision,
                    new_revision=next_revision,
                    old_value={
                        "source_state": "present",
                        "lifecycle_status": str(row["lifecycle_status"]),
                    },
                    new_value={
                        "source_state": "missing",
                        "lifecycle_status": "archived",
                    },
                    occurred_at=now,
                )
                counters["missing_count"] += 1

            completed_at = utc_now()
            connection.execute(
                """
                UPDATE research_workspace_sync_run SET
                    completed_at=?,status='completed',discovered_count=?,
                    created_count=?,updated_count=?,moved_count=?,missing_count=?,
                    restored_count=?,issue_count=0,issues_json='[]'
                WHERE sync_run_id=?
                """,
                (
                    completed_at,
                    counters["discovered_count"],
                    counters["created_count"],
                    counters["updated_count"],
                    counters["moved_count"],
                    counters["missing_count"],
                    counters["restored_count"],
                    sync_run_id,
                ),
            )
        return {
            "sync_run_id": sync_run_id,
            "status": "completed",
            "started_at": started_at,
            "completed_at": completed_at,
            **counters,
            "source_signature": source_signature,
        }

    def sync_if_changed(self) -> dict[str, Any] | None:
        signature = self._quick_signature()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT source_signature FROM research_workspace_sync_run
                WHERE status='completed'
                ORDER BY completed_at DESC,sync_run_id DESC LIMIT 1
                """
            ).fetchone()
        if row is not None and str(row["source_signature"]) == signature:
            return None
        return self.sync()

    def sync_command(self, *, idempotency_key: str) -> WorkspaceCommandOutcome:
        """Expose the idempotent HTTP command while keeping startup sync receipt-free."""

        command = "workspace.sync"
        payload = {"workspace_root": str(self.root)}
        digest = self._payload_hash(command, payload)
        with self._connection() as connection:
            replay = self._replay(
                connection,
                command=command,
                idempotency_key=idempotency_key,
                payload_hash=digest,
            )
        if replay is not None:
            return replay
        report = self.sync()
        outcome = WorkspaceCommandOutcome(True, 200, data=report)
        with self._connection() as connection, immediate_transaction(connection):
            replay = self._replay(
                connection,
                command=command,
                idempotency_key=idempotency_key,
                payload_hash=digest,
            )
            if replay is not None:
                return replay
            return self._record(
                connection,
                command=command,
                idempotency_key=idempotency_key,
                payload_hash=digest,
                outcome=outcome,
            )

    def tree(
        self,
        *,
        query: str | None = None,
        status: LifecycleStatus | None = None,
        parent_node_id: str | None = None,
        node_kind: NodeKind | None = None,
    ) -> dict[str, Any]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM research_workspace_node
                WHERE source_state='present'
                ORDER BY sort_key,source_path_key
                """
            ).fetchall()
        items = [_node_data(row) for row in rows]
        by_id = {item["node_id"]: item for item in items}
        children: dict[str | None, list[dict[str, Any]]] = {}
        for item in items:
            children.setdefault(item["parent_node_id"], []).append(item)
        for group in children.values():
            group.sort(
                key=lambda item: (
                    int(item["sort_key"]),
                    str(item["display_title"]).casefold(),
                    str(item["node_id"]),
                )
            )
        project_by_node: dict[str, str | None] = {}

        def assign_project(parent: str | None, project_id: str | None = None) -> None:
            for child in children.get(parent, []):
                current_project = (
                    child["node_id"]
                    if child["node_kind"] == "project"
                    else project_id
                )
                project_by_node[child["node_id"]] = current_project
                assign_project(child["node_id"], current_project)

        assign_project(None)

        descendants: set[str] | None = None
        if parent_node_id:
            descendants = set()
            stack = [parent_node_id]
            while stack:
                current = stack.pop()
                if current in descendants:
                    continue
                descendants.add(current)
                stack.extend(
                    child["node_id"] for child in children.get(current, [])
                )

        folded = (query or "").strip().casefold()
        matched: set[str] = set()
        for item in items:
            if descendants is not None and item["node_id"] not in descendants:
                continue
            if status:
                project_id = project_by_node.get(item["node_id"])
                project = by_id.get(project_id) if project_id is not None else None
                if project is None or project["lifecycle_status"] != status:
                    continue
            if node_kind and item["node_kind"] != node_kind:
                continue
            haystack = "\n".join(
                str(item.get(key) or "")
                for key in (
                    "display_title",
                    "description",
                    "research_question",
                    "research_content",
                    "status_note",
                    "source_relative_path",
                )
            ).casefold()
            if folded and folded not in haystack:
                continue
            matched.add(item["node_id"])

        visible = set(matched)
        for node_id in tuple(matched):
            parent = by_id[node_id]["parent_node_id"]
            while parent is not None and parent not in visible:
                visible.add(parent)
                parent = by_id.get(parent, {}).get("parent_node_id")
        filtering = bool(folded or status or parent_node_id or node_kind)
        if not filtering:
            visible = set(by_id)

        def branch(parent: str | None, depth: int = 0) -> list[dict[str, Any]]:
            result: list[dict[str, Any]] = []
            for item in children.get(parent, []):
                if item["node_id"] not in visible:
                    continue
                value = dict(item)
                value["depth"] = depth
                value["matched"] = item["node_id"] in matched
                value["children"] = branch(item["node_id"], depth + 1)
                if value["page_url"] is None:
                    value["page_url"] = next(
                        (
                            child["page_url"]
                            for child in value["children"]
                            if child["page_url"] is not None
                        ),
                        None,
                    )
                result.append(value)
            return result

        stats = {
            lifecycle: sum(
                1
                for item in items
                if item["node_kind"] == "project"
                and item["lifecycle_status"] == lifecycle
                and item["source_state"] == "present"
            )
            for lifecycle in (
                "todo",
                "in_progress",
                "review",
                "completed",
                "archived",
                "cancelled",
            )
        }
        return {
            "tree": branch(None),
            "items": [item for item in items if item["node_id"] in visible],
            "matched_count": sum(
                1
                for item in items
                if item["node_id"] in matched and item["node_kind"] != "system"
            ),
            "total_count": len(items) - sum(item["node_kind"] == "system" for item in items),
            "stats": stats,
            "filters": {
                "query": query or "",
                "status": status,
                "parent_node_id": parent_node_id,
                "node_kind": node_kind,
            },
        }

    def get_node(self, node_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM research_workspace_node WHERE node_id=?", (node_id,)
            ).fetchone()
            if row is None:
                raise WorkspaceNotFound(node_id)
            child_rows = connection.execute(
                """
                SELECT *
                FROM research_workspace_node
                WHERE parent_node_id=? AND source_state='present'
                ORDER BY sort_key,COALESCE(title_override,default_title),node_id
                """,
                (node_id,),
            ).fetchall()
            events = connection.execute(
                """
                SELECT event.event_id,event.event_kind,event.old_value_json,
                       event.new_value_json,event.note,event.occurred_at,
                       event.prior_revision,event.new_revision,
                       actor.actor_kind,actor.display_name
                FROM research_workspace_event AS event
                LEFT JOIN actor ON actor.actor_id=event.actor_id
                WHERE event.node_id=?
                ORDER BY event.occurred_at DESC,event.event_id DESC LIMIT 50
                """,
                (node_id,),
            ).fetchall()
            derived_page_urls = {
                str(item["node_id"]): self._first_descendant_page_url(
                    connection, str(item["node_id"])
                )
                for item in child_rows
                if item["published_page_url"] is None
            }
            selected_page_url = (
                self._first_descendant_page_url(connection, node_id)
                if row["published_page_url"] is None
                else None
            )
        data = _node_data(row)
        data["children"] = [_node_data(item) for item in child_rows]
        for child in data["children"]:
            if child["page_url"] is None:
                child["page_url"] = derived_page_urls[str(child["node_id"])]
        if data["page_url"] is None:
            data["page_url"] = selected_page_url
        data["events"] = [
            {
                "event_id": str(item["event_id"]),
                "event_kind": str(item["event_kind"]),
                "old_value": (
                    json.loads(str(item["old_value_json"]))
                    if item["old_value_json"] is not None
                    else None
                ),
                "new_value": (
                    json.loads(str(item["new_value_json"]))
                    if item["new_value_json"] is not None
                    else None
                ),
                "note": str(item["note"]) if item["note"] is not None else None,
                "occurred_at": str(item["occurred_at"]),
                "prior_revision": (
                    int(item["prior_revision"])
                    if item["prior_revision"] is not None
                    else None
                ),
                "new_revision": int(item["new_revision"]),
                "actor": (
                    {
                        "actor_kind": str(item["actor_kind"]),
                        "display_name": str(item["display_name"]),
                    }
                    if item["actor_kind"] is not None
                    else None
                ),
            }
            for item in events
        ]
        data["comments"] = self.list_comments(node_id)
        return data

    @staticmethod
    def _first_descendant_page_url(
        connection: sqlite3.Connection, node_id: str
    ) -> str | None:
        row = connection.execute(
            """
            WITH RECURSIVE descendants(node_id,depth) AS (
                SELECT child.node_id,1
                FROM research_workspace_node AS child
                WHERE child.parent_node_id=? AND child.source_state='present'
                UNION ALL
                SELECT child.node_id,parent.depth+1
                FROM research_workspace_node AS child
                JOIN descendants AS parent ON child.parent_node_id=parent.node_id
                WHERE child.source_state='present'
            )
            SELECT node.published_page_url
            FROM descendants
            JOIN research_workspace_node AS node USING(node_id)
            WHERE node.published_page_url IS NOT NULL
            ORDER BY descendants.depth,node.sort_key,node.source_path_key,node.node_id
            LIMIT 1
            """,
            (node_id,),
        ).fetchone()
        return str(row["published_page_url"]) if row is not None else None

    def project_options(self) -> list[dict[str, str]]:
        """Return stable top-level project choices for hierarchy-preserving filters."""

        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT node_id,COALESCE(title_override,default_title) AS display_title
                FROM research_workspace_node
                WHERE node_kind='project' AND source_state='present'
                ORDER BY sort_key,display_title,node_id
                """
            ).fetchall()
        return [
            {
                "node_id": str(row["node_id"]),
                "display_title": str(row["display_title"]),
            }
            for row in rows
        ]

    def recent_updates(self, *, limit: int = 12) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 100)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT event.event_id,event.event_kind,event.note,event.occurred_at,
                       event.node_id,node.default_title,node.title_override,
                       node.research_id,node.document_id,node.published_page_url,
                       node.source_relative_path,
                       actor.display_name
                FROM research_workspace_event AS event
                JOIN research_workspace_node AS node ON node.node_id=event.node_id
                LEFT JOIN actor ON actor.actor_id=event.actor_id
                WHERE event.event_kind IN (
                    'discovered','content_updated','moved','restored',
                    'metadata_updated','status_changed'
                )
                  AND node.node_kind <> 'system'
                  AND node.source_state='present'
                ORDER BY event.occurred_at DESC,event.event_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "event_id": str(row["event_id"]),
                "event_kind": str(row["event_kind"]),
                "node_id": str(row["node_id"]),
                "title": str(row["title_override"] or row["default_title"]),
                "source_relative_path": str(row["source_relative_path"]),
                "note": str(row["note"]) if row["note"] is not None else None,
                "occurred_at": str(row["occurred_at"]),
                "actor_display_name": (
                    str(row["display_name"]) if row["display_name"] is not None else None
                ),
                "page_url": (
                    str(row["published_page_url"])
                    if row["published_page_url"] is not None
                    else f"/?node={row['node_id']}"
                ),
            }
            for row in rows
        ]

    def create_project(
        self,
        *,
        title: str,
        description: str | None,
        research_question: str | None,
        research_content: str | None,
        lifecycle_status: LifecycleStatus,
        status_note: str | None,
        actor: ActorInput,
        idempotency_key: str,
    ) -> WorkspaceCommandOutcome:
        """Create a top-level source directory, then register its editable state."""

        command = "workspace.project.create"
        try:
            project_title = _manual_project_title(title)
            directory_title = _project_directory_component(project_title)
        except ValueError as error:
            return WorkspaceCommandOutcome(
                False,
                422,
                error_code="invalid_project_title",
                error_message=str(error),
            )
        description = description.strip() if description else None
        research_question = research_question.strip() if research_question else None
        research_content = research_content.strip() if research_content else None
        status_note = status_note.strip() if status_note else None
        if lifecycle_status not in {
            "todo", "in_progress", "review", "completed", "archived", "cancelled"
        }:
            return WorkspaceCommandOutcome(
                False,
                422,
                error_code="invalid_lifecycle_status",
                error_message="研究状态不在统一生命周期中。",
            )
        payload = {
            "title": project_title,
            "description": description,
            "research_question": research_question,
            "research_content": research_content,
            "lifecycle_status": lifecycle_status,
            "status_note": status_note,
            "actor": actor.model_dump(mode="json"),
        }
        digest = self._payload_hash(command, payload)

        with _PROJECT_CREATE_LOCK:
            with self._connection() as connection:
                replay = self._replay(
                    connection,
                    command=command,
                    idempotency_key=idempotency_key,
                    payload_hash=digest,
                )
            if replay is not None:
                return replay

            root = self._validate_root()
            orders: list[int] = []
            for child in root.iterdir():
                info = child.lstat()
                if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                    continue
                order, _ = _display_component(child.name)
                if order < 100_000:
                    orders.append(order)
            order = max(orders, default=0) + 1
            while True:
                if order > 9_999:
                    return WorkspaceCommandOutcome(
                        False,
                        409,
                        error_code="project_sequence_exhausted",
                        error_message="研究专项序号已达到目录协议上限。",
                    )
                relative_path = f"{order:02d}_{directory_title}"
                target = root / relative_path
                if not target.exists():
                    break
                order += 1

            display_title = f"Q{order}｜{project_title}"
            readme = _project_readme(
                display_title,
                description,
                research_question,
                research_content,
            )
            readme_path = target / "README.md"
            target.mkdir()
            try:
                with readme_path.open("x", encoding="utf-8", newline="\n") as handle:
                    handle.write(readme)
                self.sync()
                with self._connection() as connection, immediate_transaction(connection):
                    replay = self._replay(
                        connection,
                        command=command,
                        idempotency_key=idempotency_key,
                        payload_hash=digest,
                    )
                    if replay is not None:
                        return replay
                    row = connection.execute(
                        """
                        SELECT * FROM research_workspace_node
                        WHERE source_path_key=? AND node_kind='project'
                        """,
                        (_path_key(relative_path),),
                    ).fetchone()
                    if row is None:
                        raise WorkspaceError(
                            "new research project was not discovered during synchronization"
                        )
                    actor_id = self._actor_id(connection, actor)
                    old = _node_data(row)
                    next_revision = int(row["revision"]) + 1
                    now = utc_now()
                    connection.execute(
                        """
                        UPDATE research_workspace_node SET
                            title_override=?,description_override=?,
                            research_question_override=?,research_content_override=?,
                            lifecycle_status=?,status_note=?,updated_at=?,revision=?
                        WHERE node_id=?
                        """,
                        (
                            display_title,
                            description,
                            research_question,
                            research_content,
                            lifecycle_status,
                            status_note,
                            now,
                            next_revision,
                            row["node_id"],
                        ),
                    )
                    updated = connection.execute(
                        "SELECT * FROM research_workspace_node WHERE node_id=?",
                        (row["node_id"],),
                    ).fetchone()
                    assert updated is not None
                    data = _node_data(updated)
                    event_kind = (
                        "status_changed"
                        if lifecycle_status != row["lifecycle_status"]
                        else "metadata_updated"
                    )
                    self._event(
                        connection,
                        node_id=str(row["node_id"]),
                        event_kind=event_kind,
                        actor_id=actor_id,
                        prior_revision=int(row["revision"]),
                        new_revision=next_revision,
                        old_value={
                            "display_title": old["display_title"],
                            "description": old["description"],
                            "research_question": old["research_question"],
                            "research_content": old["research_content"],
                            "lifecycle_status": old["lifecycle_status"],
                            "status_note": old["status_note"],
                        },
                        new_value={
                            "display_title": data["display_title"],
                            "description": data["description"],
                            "research_question": data["research_question"],
                            "research_content": data["research_content"],
                            "lifecycle_status": data["lifecycle_status"],
                            "status_note": data["status_note"],
                        },
                        note=status_note if event_kind == "status_changed" else None,
                        occurred_at=now,
                    )
                    return self._record(
                        connection,
                        command=command,
                        idempotency_key=idempotency_key,
                        payload_hash=digest,
                        outcome=WorkspaceCommandOutcome(True, 201, data=data),
                    )
            except BaseException:
                if readme_path.is_file():
                    readme_path.unlink()
                if target.is_dir():
                    target.rmdir()
                try:
                    self.sync()
                except BaseException:
                    pass
                raise

    def update_node(
        self,
        node_id: str,
        changes: dict[str, Any],
        actor: ActorInput,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> WorkspaceCommandOutcome:
        command = "workspace.node.update"
        editable = {
            "title",
            "description",
            "research_question",
            "research_content",
            "lifecycle_status",
            "status_note",
        }
        if not changes or set(changes) - editable:
            return WorkspaceCommandOutcome(
                False, 422, error_code="invalid_node_update",
                error_message="至少提供一个受支持的研究节点字段。"
            )
        payload = {
            "node_id": node_id,
            "changes": changes,
            "actor": actor.model_dump(mode="json"),
            "expected_revision": expected_revision,
        }
        digest = self._payload_hash(command, payload)
        with self._connection() as connection, immediate_transaction(connection):
            replay = self._replay(
                connection, command=command, idempotency_key=idempotency_key,
                payload_hash=digest
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            row = connection.execute(
                "SELECT * FROM research_workspace_node WHERE node_id=?", (node_id,)
            ).fetchone()
            if row is None:
                outcome = WorkspaceCommandOutcome(
                    False, 404, error_code="node_not_found",
                    error_message="研究节点不存在。"
                )
                return self._record(
                    connection, command=command, idempotency_key=idempotency_key,
                    payload_hash=digest, outcome=outcome
                )
            project_only = {
                "research_question",
                "research_content",
                "lifecycle_status",
                "status_note",
            }
            if str(row["node_kind"]) != "project" and set(changes) & project_only:
                outcome = WorkspaceCommandOutcome(
                    False,
                    422,
                    error_code="project_fields_require_project_node",
                    error_message="研究问题、研究内容与研究状态只在专项研究层级维护。",
                )
                return self._record(
                    connection,
                    command=command,
                    idempotency_key=idempotency_key,
                    payload_hash=digest,
                    outcome=outcome,
                )
            if int(row["revision"]) != expected_revision:
                outcome = WorkspaceCommandOutcome(
                    False, 409, error_code="revision_conflict",
                    error_message="研究节点已被其他写入更新，请刷新后重试。"
                )
                return self._record(
                    connection, command=command, idempotency_key=idempotency_key,
                    payload_hash=digest, outcome=outcome
                )
            title = changes.get("title", row["title_override"])
            description = changes.get("description", row["description_override"])
            research_question = changes.get(
                "research_question", row["research_question_override"]
            )
            research_content = changes.get(
                "research_content", row["research_content_override"]
            )
            lifecycle = changes.get("lifecycle_status", row["lifecycle_status"])
            status_note = changes.get("status_note", row["status_note"])
            if isinstance(title, str):
                title = title.strip() or None
            if isinstance(description, str):
                description = description.strip() or None
            if isinstance(research_question, str):
                research_question = research_question.strip() or None
            if isinstance(research_content, str):
                research_content = research_content.strip() or None
            if isinstance(status_note, str):
                status_note = status_note.strip() or None
            if title is not None and len(str(title)) > 500:
                return WorkspaceCommandOutcome(
                    False, 422, error_code="invalid_title",
                    error_message="标题不得超过 500 字符。"
                )
            if description is not None and len(str(description)) > 8_000:
                return WorkspaceCommandOutcome(
                    False, 422, error_code="invalid_description",
                    error_message="说明不得超过 8000 字符。"
                )
            if research_question is not None and len(str(research_question)) > 8_000:
                return WorkspaceCommandOutcome(
                    False,
                    422,
                    error_code="invalid_research_question",
                    error_message="研究问题不得超过 8000 字符。",
                )
            if research_content is not None and len(str(research_content)) > 20_000:
                return WorkspaceCommandOutcome(
                    False,
                    422,
                    error_code="invalid_research_content",
                    error_message="研究内容不得超过 20000 字符。",
                )
            if lifecycle not in {
                "todo", "in_progress", "review", "completed", "archived", "cancelled"
            }:
                return WorkspaceCommandOutcome(
                    False, 422, error_code="invalid_lifecycle_status",
                    error_message="研究状态不在统一生命周期中。"
                )
            old = _node_data(row)
            next_revision = expected_revision + 1
            now = utc_now()
            connection.execute(
                """
                UPDATE research_workspace_node SET
                    title_override=?,description_override=?,
                    research_question_override=?,research_content_override=?,
                    lifecycle_status=?,status_note=?,
                    updated_at=?,revision=? WHERE node_id=?
                """,
                (
                    title,
                    description,
                    research_question,
                    research_content,
                    lifecycle,
                    status_note,
                    now,
                    next_revision,
                    node_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM research_workspace_node WHERE node_id=?", (node_id,)
            ).fetchone()
            assert updated is not None
            data = _node_data(updated)
            event_kind = (
                "status_changed"
                if lifecycle != row["lifecycle_status"]
                else "metadata_updated"
            )
            self._event(
                connection,
                node_id=node_id,
                event_kind=event_kind,
                actor_id=actor_id,
                prior_revision=expected_revision,
                new_revision=next_revision,
                old_value={
                    key: old[key]
                    for key in (
                        "display_title",
                        "description",
                        "research_question",
                        "research_content",
                        "lifecycle_status",
                        "status_note",
                    )
                },
                new_value={
                    key: data[key]
                    for key in (
                        "display_title",
                        "description",
                        "research_question",
                        "research_content",
                        "lifecycle_status",
                        "status_note",
                    )
                },
                note=status_note if event_kind == "status_changed" else None,
                occurred_at=now,
            )
            return self._record(
                connection, command=command, idempotency_key=idempotency_key,
                payload_hash=digest,
                outcome=WorkspaceCommandOutcome(True, 200, data=data)
            )

    def list_comments(self, node_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT comment.comment_id,comment.node_id,comment.body,
                       comment.created_at,comment.updated_at,comment.revision,
                       actor.actor_kind,actor.display_name
                FROM research_workspace_comment AS comment
                JOIN actor ON actor.actor_id=comment.actor_id
                WHERE comment.node_id=? AND comment.deleted_at IS NULL
                ORDER BY comment.created_at,comment.comment_id
                """,
                (node_id,),
            ).fetchall()
        return [
            {
                "comment_id": str(row["comment_id"]),
                "node_id": str(row["node_id"]),
                "content": str(row["body"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "revision": int(row["revision"]),
                "actor": {
                    "actor_kind": str(row["actor_kind"]),
                    "display_name": str(row["display_name"]),
                },
            }
            for row in rows
        ]

    def create_comment(
        self,
        node_id: str,
        actor: ActorInput,
        body: str,
        *,
        idempotency_key: str,
    ) -> WorkspaceCommandOutcome:
        command = "workspace.comment.create"
        body = body.strip()
        payload = {
            "node_id": node_id,
            "actor": actor.model_dump(mode="json"),
            "body": body,
        }
        digest = self._payload_hash(command, payload)
        with self._connection() as connection, immediate_transaction(connection):
            replay = self._replay(
                connection, command=command, idempotency_key=idempotency_key,
                payload_hash=digest
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            node = connection.execute(
                "SELECT * FROM research_workspace_node WHERE node_id=?", (node_id,)
            ).fetchone()
            if node is None:
                outcome = WorkspaceCommandOutcome(
                    False, 404, error_code="node_not_found",
                    error_message="研究节点不存在。"
                )
            elif not body or len(body) > 8_000:
                outcome = WorkspaceCommandOutcome(
                    False, 422, error_code="invalid_comment",
                    error_message="评论内容不能为空且不得超过 8000 字符。"
                )
            else:
                now = utc_now()
                comment_id = new_public_id("wcmt")
                connection.execute(
                    """
                    INSERT INTO research_workspace_comment(
                        comment_id,node_id,actor_id,body,created_at,updated_at,
                        revision,deleted_at
                    ) VALUES(?,?,?,?,?,?,1,NULL)
                    """,
                    (comment_id, node_id, actor_id, body, now, now),
                )
                body_hash = sha256_hex(body.encode("utf-8"))
                connection.execute(
                    """
                    INSERT INTO research_workspace_comment_event(
                        comment_event_id,comment_id,event_type,old_body_hash,
                        new_body_hash,actor_id,revision,occurred_at
                    ) VALUES(?,?,'create',NULL,?,?,1,?)
                    """,
                    (new_public_id("wcevt"), comment_id, body_hash, actor_id, now),
                )
                prior_revision = int(node["revision"])
                next_revision = prior_revision
                next_revision += 1
                connection.execute(
                    """
                    UPDATE research_workspace_node SET updated_at=?,revision=?
                    WHERE node_id=?
                    """,
                    (now, next_revision, node_id),
                )
                self._event(
                    connection,
                    node_id=node_id,
                    event_kind="comment_created",
                    actor_id=actor_id,
                    prior_revision=prior_revision,
                    new_revision=next_revision,
                    new_value={"comment_id": comment_id},
                    occurred_at=now,
                )
                outcome = WorkspaceCommandOutcome(
                    True,
                    201,
                    data={
                        "comment_id": comment_id,
                        "node_id": node_id,
                        "content": body,
                        "actor": {
                            "actor_kind": actor.actor_kind,
                            "display_name": _actor_name(actor),
                        },
                        "created_at": now,
                        "updated_at": now,
                        "revision": 1,
                        "node_revision": next_revision,
                    },
                )
            return self._record(
                connection, command=command, idempotency_key=idempotency_key,
                payload_hash=digest, outcome=outcome
            )

    def change_comment(
        self,
        comment_id: str,
        actor: ActorInput,
        *,
        body: str | None,
        expected_revision: int,
        idempotency_key: str,
        delete: bool,
    ) -> WorkspaceCommandOutcome:
        command = "workspace.comment.delete" if delete else "workspace.comment.update"
        normalized = None if body is None else body.strip()
        payload = {
            "comment_id": comment_id,
            "actor": actor.model_dump(mode="json"),
            "body": normalized,
            "expected_revision": expected_revision,
        }
        digest = self._payload_hash(command, payload)
        with self._connection() as connection, immediate_transaction(connection):
            replay = self._replay(
                connection, command=command, idempotency_key=idempotency_key,
                payload_hash=digest
            )
            if replay is not None:
                return replay
            actor_id = self._actor_id(connection, actor)
            row = connection.execute(
                """
                SELECT comment.*
                FROM research_workspace_comment AS comment
                WHERE comment.comment_id=?
                """,
                (comment_id,),
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                outcome = WorkspaceCommandOutcome(
                    False, 404, error_code="comment_not_found",
                    error_message="评论不存在或已删除。"
                )
            elif int(row["revision"]) != expected_revision:
                outcome = WorkspaceCommandOutcome(
                    False, 409, error_code="revision_conflict",
                    error_message="评论已被其他写入更新，请刷新后重试。"
                )
            elif not delete and (not normalized or len(normalized) > 8_000):
                outcome = WorkspaceCommandOutcome(
                    False, 422, error_code="invalid_comment",
                    error_message="评论内容不能为空且不得超过 8000 字符。"
                )
            else:
                now = utc_now()
                node = connection.execute(
                    "SELECT revision FROM research_workspace_node WHERE node_id=?",
                    (row["node_id"],),
                ).fetchone()
                if node is None:
                    outcome = WorkspaceCommandOutcome(
                        False, 404, error_code="node_not_found",
                        error_message="评论所属研究节点不存在。"
                    )
                    return self._record(
                        connection, command=command,
                        idempotency_key=idempotency_key,
                        payload_hash=digest, outcome=outcome
                    )
                old_hash = sha256_hex(str(row["body"]).encode("utf-8"))
                next_comment_revision = expected_revision + 1
                if delete:
                    connection.execute(
                        """
                        UPDATE research_workspace_comment
                        SET updated_at=?,revision=?,deleted_at=? WHERE comment_id=?
                        """,
                        (now, next_comment_revision, now, comment_id),
                    )
                    new_hash = None
                    event_type = "delete"
                else:
                    assert normalized is not None
                    connection.execute(
                        """
                        UPDATE research_workspace_comment
                        SET body=?,updated_at=?,revision=? WHERE comment_id=?
                        """,
                        (normalized, now, next_comment_revision, comment_id),
                    )
                    new_hash = sha256_hex(normalized.encode("utf-8"))
                    event_type = "update"
                connection.execute(
                    """
                    INSERT INTO research_workspace_comment_event(
                        comment_event_id,comment_id,event_type,old_body_hash,
                        new_body_hash,actor_id,revision,occurred_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        new_public_id("wcevt"), comment_id, event_type, old_hash,
                        new_hash, actor_id, next_comment_revision, now
                    ),
                )
                prior_node_revision = int(node["revision"])
                next_node_revision = prior_node_revision
                next_node_revision += 1
                connection.execute(
                    """
                    UPDATE research_workspace_node SET updated_at=?,revision=?
                    WHERE node_id=?
                    """,
                    (now, next_node_revision, row["node_id"]),
                )
                self._event(
                    connection,
                    node_id=str(row["node_id"]),
                    event_kind="comment_deleted" if delete else "comment_updated",
                    actor_id=actor_id,
                    prior_revision=prior_node_revision,
                    new_revision=next_node_revision,
                    old_value={"comment_id": comment_id, "body_sha256": old_hash},
                    new_value=(
                        None
                        if delete
                        else {"comment_id": comment_id, "body_sha256": new_hash}
                    ),
                    occurred_at=now,
                )
                outcome = WorkspaceCommandOutcome(
                    True,
                    200,
                    data={
                        "comment_id": comment_id,
                        "node_id": str(row["node_id"]),
                        "revision": next_comment_revision,
                        "node_revision": next_node_revision,
                        "deleted": delete,
                        "content": None if delete else normalized,
                        "updated_at": now,
                    },
                )
            return self._record(
                connection, command=command, idempotency_key=idempotency_key,
                payload_hash=digest, outcome=outcome
            )
