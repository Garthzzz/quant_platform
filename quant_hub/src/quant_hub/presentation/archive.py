"""Archive 展示覆盖与内部链接目录。

本模块只读取随代码发布的展示 manifest。研究事实、原始标题和正文仍由
``reference/archive`` 的不可变快照与 Archive 数据库负责；这里的文字只用于
页面命名、导语、摘要和阅读导航，绝不写回来源或伪装成来源结论。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import posixpath
import re
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit


class ArchivePresentationError(RuntimeError):
    """展示 manifest 或内部链接身份不完整。"""


@dataclass(frozen=True, slots=True)
class InternalArchiveLink:
    """一次相对 Markdown 链接在当前 active release 中的展示目标。"""

    state: str
    title: str
    url: str
    source_path: str | None
    reason: str | None = None


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ArchivePresentationError(f"{field} must be a non-empty string")
    return value.strip()


def _text_map(value: object, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ArchivePresentationError(f"{field} must be an object")
    rows: dict[str, str] = {}
    for key, item in value.items():
        clean_key = _required_text(key, f"{field} key")
        rows[clean_key] = _required_text(item, f"{field}.{clean_key}")
    return rows


def _text_list(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ArchivePresentationError(f"{field} must be a string array")
    return tuple(item.strip().replace("\\", "/") for item in value)


def _archive_path(value: object, field: str) -> str:
    """校验 manifest 中以 Archive 根为基准的精确 Markdown 路径。"""

    path = _required_text(value, field).replace("\\", "/")
    normalized = posixpath.normpath(path)
    if (
        path.startswith("/")
        or normalized in {".", ".."}
        or normalized.startswith("../")
        or not normalized.lower().endswith((".md", ".markdown"))
    ):
        raise ArchivePresentationError(
            f"{field} must be an Archive-root Markdown path"
        )
    return normalized


def _archive_directory_path(value: object, field: str) -> str:
    """校验 manifest 中以 Archive 根为基准的目录身份。"""

    path = _required_text(value, field).replace("\\", "/").rstrip("/")
    normalized = posixpath.normpath(path)
    if (
        path.startswith("/")
        or normalized in {".", ".."}
        or normalized.startswith("../")
        or normalized.lower().endswith((".md", ".markdown"))
    ):
        raise ArchivePresentationError(
            f"{field} must be an Archive-root directory path"
        )
    return normalized


def _context_reference(value: object, field: str) -> str:
    reference = unquote(_required_text(value, field)).replace("\\", "/")
    split = urlsplit(reference)
    if split.scheme or split.netloc or reference.startswith(("/", "\\", "#")):
        raise ArchivePresentationError(f"{field} must be a relative source reference")
    return reference


class ArchivePresentation:
    """经版本化 manifest 驱动的只读 Archive 展示策略。"""

    SCHEMA_VERSION = "qrh-archive-presentation/v1"

    def __init__(self, payload: Mapping[str, Any], *, source: Path | None = None):
        if payload.get("schema_version") != self.SCHEMA_VERSION:
            raise ArchivePresentationError("archive presentation schema is unsupported")
        self.source = source
        home = payload.get("home")
        if not isinstance(home, dict):
            raise ArchivePresentationError("home presentation metadata is required")
        self.home = {
            "eyebrow": _required_text(home.get("eyebrow"), "home.eyebrow"),
            "title": _required_text(home.get("title"), "home.title"),
            "introduction": _required_text(
                home.get("introduction"), "home.introduction"
            ),
        }
        self.heading_overrides = _text_map(
            payload.get("heading_overrides"), "heading_overrides"
        )
        raw_path_heading_overrides = payload.get("heading_overrides_by_path", {})
        if not isinstance(raw_path_heading_overrides, dict):
            raise ArchivePresentationError(
                "heading_overrides_by_path must be an object"
            )
        self.path_heading_overrides: dict[str, dict[str, str]] = {}
        for raw_path, overrides in raw_path_heading_overrides.items():
            source_path = _archive_path(
                raw_path, "heading_overrides_by_path source path"
            )
            self.path_heading_overrides[source_path] = _text_map(
                overrides, f"heading_overrides_by_path.{source_path}"
            )
        self.heading_token_overrides = _text_map(
            payload.get("heading_token_overrides"), "heading_token_overrides"
        )
        self.visible_text_overrides = _text_map(
            payload.get("visible_text_overrides"), "visible_text_overrides"
        )
        internal_links = payload.get("internal_links", {})
        if not isinstance(internal_links, dict):
            raise ArchivePresentationError("internal_links must be an object")
        self.internal_link_label_overrides = _text_map(
            internal_links.get("label_overrides"),
            "internal_links.label_overrides",
        )
        provenance = internal_links.get("historical_provenance", {})
        if not isinstance(provenance, dict):
            raise ArchivePresentationError(
                "internal_links.historical_provenance must be an object"
            )
        provenance_prefixes = provenance.get("path_prefixes", [])
        if not isinstance(provenance_prefixes, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in provenance_prefixes
        ):
            raise ArchivePresentationError(
                "internal_links.historical_provenance.path_prefixes "
                "must be a string array"
            )
        self.historical_provenance_prefixes = tuple(
            item.strip().replace("\\", "/") for item in provenance_prefixes
        )
        self.historical_provenance_label = (
            _required_text(
                provenance.get("label"),
                "internal_links.historical_provenance.label",
            )
            if self.historical_provenance_prefixes
            else ""
        )
        raw_aliases = internal_links.get("aliases", {})
        if not isinstance(raw_aliases, dict):
            raise ArchivePresentationError("internal_links.aliases must be an object")
        self.internal_link_aliases: dict[str, dict[str, str]] = {}
        for source_path, raw_alias in raw_aliases.items():
            alias_path = _archive_path(
                source_path, "internal_links.aliases source path"
            )
            if not isinstance(raw_alias, dict):
                raise ArchivePresentationError(
                    f"internal_links.aliases.{alias_path} must be an object"
                )
            self.internal_link_aliases[alias_path] = {
                "target_path": _archive_path(
                    raw_alias.get("target_path"),
                    f"internal_links.aliases.{alias_path}.target_path",
                ),
                "reason": _required_text(
                    raw_alias.get("reason"),
                    f"internal_links.aliases.{alias_path}.reason",
                ),
            }
        raw_retired_targets = internal_links.get("retired_targets", {})
        if not isinstance(raw_retired_targets, dict):
            raise ArchivePresentationError(
                "internal_links.retired_targets must be an object"
            )
        self.retired_internal_targets: dict[
            str, dict[str, str | None]
        ] = {}
        for source_path, raw_target in raw_retired_targets.items():
            retired_path = _archive_path(
                source_path, "internal_links.retired_targets source path"
            )
            field = f"internal_links.retired_targets.{retired_path}"
            if not isinstance(raw_target, dict):
                raise ArchivePresentationError(f"{field} must be an object")
            state = _required_text(raw_target.get("state"), f"{field}.state")
            if state not in {"resolved", "label"}:
                raise ArchivePresentationError(
                    f"{field}.state must be resolved or label"
                )
            target_path: str | None = None
            fragment: str | None = None
            if state == "resolved":
                target_path = _archive_path(
                    raw_target.get("target_path"), f"{field}.target_path"
                )
                raw_fragment = raw_target.get("fragment")
                if raw_fragment is not None:
                    fragment = _required_text(raw_fragment, f"{field}.fragment")
            self.retired_internal_targets[retired_path] = {
                "state": state,
                "target_path": target_path,
                "fragment": fragment,
                "title": _required_text(raw_target.get("title"), f"{field}.title"),
                "reason": _required_text(
                    raw_target.get("reason"), f"{field}.reason"
                ),
            }
        raw_directories = internal_links.get("directory_aliases", {})
        if not isinstance(raw_directories, dict):
            raise ArchivePresentationError(
                "internal_links.directory_aliases must be an object"
            )
        self.internal_directory_aliases: dict[str, dict[str, str | None]] = {}
        for source_directory, raw_alias in raw_directories.items():
            directory_path = _archive_directory_path(
                source_directory,
                "internal_links.directory_aliases source directory",
            )
            if not isinstance(raw_alias, dict):
                raise ArchivePresentationError(
                    f"internal_links.directory_aliases.{directory_path} must be an object"
                )
            fragment = raw_alias.get("fragment")
            if fragment is not None and (
                not isinstance(fragment, str) or not fragment.strip()
            ):
                raise ArchivePresentationError(
                    f"internal_links.directory_aliases.{directory_path}.fragment "
                    "must be a non-empty string when present"
                )
            self.internal_directory_aliases[directory_path] = {
                "target_path": _archive_path(
                    raw_alias.get("target_path"),
                    f"internal_links.directory_aliases.{directory_path}.target_path",
                ),
                "fragment": fragment.strip() if isinstance(fragment, str) else None,
                "title": _required_text(
                    raw_alias.get("title"),
                    f"internal_links.directory_aliases.{directory_path}.title",
                ),
                "reason": _required_text(
                    raw_alias.get("reason"),
                    f"internal_links.directory_aliases.{directory_path}.reason",
                ),
            }

        raw_contextual = internal_links.get("contextual_overrides", [])
        if not isinstance(raw_contextual, list):
            raise ArchivePresentationError(
                "internal_links.contextual_overrides must be an array"
            )
        self.internal_contextual_overrides: dict[
            tuple[str, str], dict[str, str | None]
        ] = {}
        for position, raw_override in enumerate(raw_contextual):
            field = f"internal_links.contextual_overrides[{position}]"
            if not isinstance(raw_override, dict):
                raise ArchivePresentationError(f"{field} must be an object")
            source_path = _archive_path(
                raw_override.get("source_path"), f"{field}.source_path"
            )
            reference = _context_reference(
                raw_override.get("reference"), f"{field}.reference"
            )
            state = _required_text(raw_override.get("state"), f"{field}.state")
            if state not in {"resolved", "provenance"}:
                raise ArchivePresentationError(
                    f"{field}.state must be resolved or provenance"
                )
            key = (source_path, reference)
            if key in self.internal_contextual_overrides:
                raise ArchivePresentationError(
                    f"duplicate contextual Archive link override: {source_path} {reference}"
                )
            target_path: str | None = None
            fragment: str | None = None
            if state == "resolved":
                target_path = _archive_path(
                    raw_override.get("target_path"), f"{field}.target_path"
                )
                raw_fragment = raw_override.get("fragment")
                if raw_fragment is not None:
                    fragment = _required_text(raw_fragment, f"{field}.fragment")
            self.internal_contextual_overrides[key] = {
                "state": state,
                "target_path": target_path,
                "fragment": fragment,
                "title": _required_text(raw_override.get("title"), f"{field}.title"),
                "reason": _required_text(raw_override.get("reason"), f"{field}.reason"),
            }

        raw_assets = internal_links.get("assets", {})
        if not isinstance(raw_assets, dict):
            raise ArchivePresentationError("internal_links.assets must be an object")
        self.internal_assets_by_path: dict[str, dict[str, Any]] = {}
        self.internal_assets_by_id: dict[str, dict[str, Any]] = {}
        for source_path, raw_asset in raw_assets.items():
            field = f"internal_links.assets.{source_path}"
            if not isinstance(raw_asset, dict):
                raise ArchivePresentationError(f"{field} must be an object")
            normalized_path = _required_text(source_path, f"{field} path").replace(
                "\\", "/"
            )
            normalized_path = posixpath.normpath(normalized_path)
            if (
                normalized_path in {".", ".."}
                or normalized_path.startswith("../")
                or normalized_path.startswith("/")
                or normalized_path.lower().endswith((".md", ".markdown"))
            ):
                raise ArchivePresentationError(
                    f"{field} must identify a non-Markdown Archive file"
                )
            asset_id = _required_text(raw_asset.get("asset_id"), f"{field}.asset_id")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,79}", asset_id):
                raise ArchivePresentationError(f"{field}.asset_id is invalid")
            digest = _required_text(raw_asset.get("sha256"), f"{field}.sha256").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ArchivePresentationError(f"{field}.sha256 is invalid")
            size = raw_asset.get("bytes")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ArchivePresentationError(f"{field}.bytes must be a non-negative integer")
            asset = {
                "asset_id": asset_id,
                "source_path": normalized_path,
                "title": _required_text(raw_asset.get("title"), f"{field}.title"),
                "sha256": digest,
                "bytes": size,
                "media_type": _required_text(
                    raw_asset.get("media_type"), f"{field}.media_type"
                ),
                "filename": _required_text(
                    raw_asset.get("filename"), f"{field}.filename"
                ),
            }
            if asset_id in self.internal_assets_by_id:
                raise ArchivePresentationError(f"duplicate Archive asset id: {asset_id}")
            self.internal_assets_by_path[normalized_path] = asset
            self.internal_assets_by_id[asset_id] = asset
        search = payload.get("search", {})
        if not isinstance(search, dict):
            raise ArchivePresentationError("search must be an object")
        excluded_markers = search.get("excluded_line_markers", [])
        if not isinstance(excluded_markers, list) or any(
            not isinstance(item, str) or not item.strip() for item in excluded_markers
        ):
            raise ArchivePresentationError(
                "search.excluded_line_markers must be a string array"
            )
        self.search_excluded_line_markers = tuple(
            item.casefold().strip() for item in excluded_markers
        )
        visibility = payload.get("visibility", {})
        if not isinstance(visibility, dict):
            raise ArchivePresentationError("visibility must be an object")
        hidden = visibility.get("hidden_research_slugs", [])
        if not isinstance(hidden, list) or any(
            not isinstance(item, str) or not item.strip() for item in hidden
        ):
            raise ArchivePresentationError(
                "visibility.hidden_research_slugs must be a string array"
            )
        self.hidden_research_slugs = frozenset(item.strip() for item in hidden)

        research = payload.get("research")
        if not isinstance(research, dict):
            raise ArchivePresentationError("research presentation metadata is required")
        self.research: dict[str, dict[str, Any]] = {}
        for slug, raw in research.items():
            clean_slug = _required_text(slug, "research slug")
            if not isinstance(raw, dict):
                raise ArchivePresentationError(f"research.{clean_slug} must be an object")
            orientation = raw.get("orientation", {})
            if not isinstance(orientation, dict):
                raise ArchivePresentationError(
                    f"research.{clean_slug}.orientation must be an object"
                )
            raw_stages = orientation.get("stages", [])
            if not isinstance(raw_stages, list):
                raise ArchivePresentationError(
                    f"research.{clean_slug}.orientation.stages must be an array"
                )
            stages: list[dict[str, str]] = []
            for index, stage in enumerate(raw_stages):
                field = f"research.{clean_slug}.orientation.stages[{index}]"
                if not isinstance(stage, dict):
                    raise ArchivePresentationError(f"{field} must be an object")
                stages.append(
                    {
                        "title": _required_text(stage.get("title"), f"{field}.title"),
                        "description": _required_text(
                            stage.get("description"), f"{field}.description"
                        ),
                    }
                )
            raw_groups = raw.get("document_groups", [])
            if not isinstance(raw_groups, list):
                raise ArchivePresentationError(
                    f"research.{clean_slug}.document_groups must be an array"
                )
            document_groups: list[dict[str, Any]] = []
            group_keys: set[str] = set()
            for index, group in enumerate(raw_groups):
                field = f"research.{clean_slug}.document_groups[{index}]"
                if not isinstance(group, dict):
                    raise ArchivePresentationError(f"{field} must be an object")
                key = _required_text(group.get("key"), f"{field}.key")
                if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", key):
                    raise ArchivePresentationError(f"{field}.key is invalid")
                if key in group_keys:
                    raise ArchivePresentationError(
                        f"research.{clean_slug} has duplicate group key {key}"
                    )
                group_keys.add(key)
                paths = _text_list(group.get("paths"), f"{field}.paths")
                prefixes = _text_list(group.get("prefixes"), f"{field}.prefixes")
                if not paths and not prefixes:
                    raise ArchivePresentationError(
                        f"{field} requires at least one path or prefix"
                    )
                document_groups.append(
                    {
                        "key": key,
                        "title": _required_text(group.get("title"), f"{field}.title"),
                        "paths": paths,
                        "prefixes": prefixes,
                    }
                )
            document_titles = _text_map(
                raw.get("document_titles"),
                f"research.{clean_slug}.document_titles",
            )
            landing_document_path = (
                _archive_path(
                    raw.get("landing_document_path"),
                    f"research.{clean_slug}.landing_document_path",
                )
                if raw.get("landing_document_path") is not None
                else None
            )
            review_document_path = (
                _archive_path(
                    raw.get("review_document_path"),
                    f"research.{clean_slug}.review_document_path",
                )
                if raw.get("review_document_path") is not None
                else None
            )
            for role, path in (
                ("landing", landing_document_path),
                ("review", review_document_path),
            ):
                if path is not None and path not in document_titles:
                    raise ArchivePresentationError(
                        f"research.{clean_slug}.{role}_document_path is not "
                        "present in document_titles"
                    )
            self.research[clean_slug] = {
                "title": _required_text(raw.get("title"), f"research.{clean_slug}.title"),
                "summary": _required_text(
                    raw.get("summary"), f"research.{clean_slug}.summary"
                ),
                "document_titles": document_titles,
                "landing_document_path": landing_document_path,
                "review_document_path": review_document_path,
                "orientation": {
                    "question": _required_text(
                        orientation.get("question", raw.get("summary")),
                        f"research.{clean_slug}.orientation.question",
                    ),
                    "decision": _required_text(
                        orientation.get("decision", raw.get("summary")),
                        f"research.{clean_slug}.orientation.decision",
                    ),
                    "stages": tuple(stages),
                },
                "document_groups": tuple(document_groups),
            }

        topics = payload.get("system_managed_topics", {})
        if not isinstance(topics, dict):
            raise ArchivePresentationError("system_managed_topics must be an object")
        keys = topics.get("suppress_until_researcher_updates", [])
        actors = topics.get("system_actor_names", [])
        for value, field in (
            (keys, "suppress_until_researcher_updates"),
            (actors, "system_actor_names"),
        ):
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise ArchivePresentationError(
                    f"system_managed_topics.{field} must be a string array"
                )
        self.system_topic_keys = frozenset(item.strip() for item in keys)
        self.system_actor_names = frozenset(item.strip() for item in actors)
        self.topic_titles = _text_map(
            topics.get("title_overrides"), "system_managed_topics.title_overrides"
        )

    @classmethod
    def default(cls) -> "ArchivePresentation":
        path = Path(__file__).with_name("archive_presentation.json")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ArchivePresentationError(
                f"cannot load archive presentation manifest: {path}"
            ) from error
        if not isinstance(payload, dict):
            raise ArchivePresentationError("archive presentation manifest must be an object")
        return cls(payload, source=path)

    def is_public_research(self, research_slug: str) -> bool:
        return research_slug not in self.hidden_research_slugs

    def research_title(self, research_slug: str, fallback: str) -> str:
        row = self.research.get(research_slug)
        return str(row["title"]) if row is not None else fallback

    def research_summary(self, research_slug: str) -> str | None:
        row = self.research.get(research_slug)
        return str(row["summary"]) if row is not None else None

    def research_orientation(self, research_slug: str) -> dict[str, Any]:
        row = self.research.get(research_slug)
        if row is None:
            return {"question": "", "decision": "", "stages": ()}
        orientation = row["orientation"]
        return {
            "question": str(orientation["question"]),
            "decision": str(orientation["decision"]),
            "stages": tuple(dict(stage) for stage in orientation["stages"]),
        }

    def research_entry_paths(self, research_slug: str) -> dict[str, str | None]:
        row = self.research.get(research_slug)
        if row is None:
            return {"landing": None, "review": None}
        return {
            "landing": row["landing_document_path"],
            "review": row["review_document_path"],
        }

    def group_documents(
        self, research_slug: str, documents: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """按展示 manifest 的显式路径分组和排序，不改变文档身份。"""

        row = self.research.get(research_slug)
        specifications = tuple(row["document_groups"]) if row is not None else ()
        grouped: dict[str, list[dict[str, Any]]] = {
            str(specification["key"]): [] for specification in specifications
        }
        unmatched: list[dict[str, Any]] = []
        for document in documents:
            path = str(document.get("source_path", "")).replace("\\", "/")
            matches = [
                specification
                for specification in specifications
                if path in specification["paths"]
                or any(path.startswith(prefix) for prefix in specification["prefixes"])
            ]
            if len(matches) > 1:
                raise ArchivePresentationError(
                    f"document is assigned to multiple presentation groups: {path}"
                )
            if not matches:
                unmatched.append(document)
            else:
                grouped[str(matches[0]["key"])].append(document)
        if specifications and unmatched:
            missing = ", ".join(
                str(document.get("source_path", "")) for document in unmatched
            )
            raise ArchivePresentationError(
                f"active documents are missing presentation groups: {missing}"
            )
        for specification in specifications:
            path_order = {
                path: index for index, path in enumerate(specification["paths"])
            }
            if path_order:
                grouped[str(specification["key"])].sort(
                    key=lambda document: (
                        path_order.get(
                            str(document.get("source_path", "")).replace("\\", "/"),
                            len(path_order),
                        ),
                        str(document.get("source_path", "")),
                    )
                )
        results = [
            {
                "key": str(specification["key"]),
                "title": str(specification["title"]),
                "documents": grouped[str(specification["key"])],
            }
            for specification in specifications
            if grouped[str(specification["key"])]
        ]
        if unmatched:
            results.append(
                {
                    "key": "additional-research",
                    "title": "研究文档",
                    "documents": unmatched,
                }
            )
        return results

    def heading_title(
        self, source_title: str, source_path: str | None = None
    ) -> str:
        path_overrides = (
            self.path_heading_overrides.get(source_path.replace("\\", "/"), {})
            if source_path
            else {}
        )
        displayed = self.visible_text(
            path_overrides.get(
                source_title, self.heading_overrides.get(source_title, source_title)
            )
        )
        for token, replacement in sorted(
            self.heading_token_overrides.items(), key=lambda item: -len(item[0])
        ):
            displayed = displayed.replace(token, replacement)
        return displayed

    def visible_text(self, source_text: str) -> str:
        """替换只面向读者的历史过程标签，不改来源正文。"""

        displayed = source_text
        for token, replacement in sorted(
            self.visible_text_overrides.items(), key=lambda item: -len(item[0])
        ):
            displayed = displayed.replace(token, replacement)
        return displayed

    def internal_link_label(self, source_label: str) -> str:
        """返回路径式链接标签的专业展示名。"""

        override = self.internal_link_label_overrides.get(source_label)
        if override is not None:
            return override
        basename = source_label.replace("\\", "/").rsplit("/", 1)[-1]
        stem = re.sub(r"\.(?:md|markdown)$", "", basename, flags=re.IGNORECASE)
        stem = re.sub(r"[*?]+", "", stem)
        return self.heading_title(re.sub(r"[_-]+", " ", stem).strip())

    def contextual_internal_link(
        self, current_source_path: str, reference: str
    ) -> dict[str, str | None] | None:
        key = (
            current_source_path.replace("\\", "/"),
            unquote(reference.strip()).replace("\\", "/"),
        )
        return self.internal_contextual_overrides.get(key)

    def directory_internal_link(
        self, normalized_directory: str
    ) -> dict[str, str | None] | None:
        return self.internal_directory_aliases.get(normalized_directory.rstrip("/"))

    def retired_internal_link(
        self, normalized_path: str
    ) -> dict[str, str | None] | None:
        """返回已退役正文目标的经审核读者语义。

        旧 Wiki 路径在来源正文中仍有研究语义，但文件可能已被用户的新研究包
        合并或撤下。只有 manifest 明确给出当前章节时才生成链接；无法唯一落到
        当前公开章节的概念保留为非链接标签，不能伪造可点击目标。
        """

        return self.retired_internal_targets.get(normalized_path)

    def internal_asset_for_path(self, normalized_path: str) -> dict[str, Any] | None:
        return self.internal_assets_by_path.get(normalized_path)

    def internal_asset(self, asset_id: str) -> dict[str, Any] | None:
        return self.internal_assets_by_id.get(asset_id)

    def is_historical_provenance_reference(self, reference: str) -> bool:
        """识别只表示旧源稿身份、并非当前 Archive 导航的路径。"""

        split = urlsplit(reference)
        if split.scheme or split.netloc or split.fragment:
            return False
        path = unquote(split.path).replace("\\", "/").lstrip("./")
        return path.lower().endswith((".md", ".markdown")) and any(
            path.startswith(prefix) for prefix in self.historical_provenance_prefixes
        )

    def public_search_text(self, source_text: str) -> str:
        return "\n".join(
            line
            for line in source_text.splitlines()
            if not any(
                marker in line.casefold()
                for marker in self.search_excluded_line_markers
            )
        )

    def document_title(
        self,
        research_slug: str,
        source_path: str | None,
        source_heading: str | None,
        fallback: str,
    ) -> str:
        row = self.research.get(research_slug)
        overrides = row["document_titles"] if row is not None else {}
        if source_path and source_path in overrides:
            return str(overrides[source_path])
        if source_heading:
            return self.heading_title(source_heading, source_path)
        return fallback

    def topic_title(self, topic_key: str, fallback: str) -> str:
        return self.topic_titles.get(topic_key, fallback)

    def suppress_system_topic(
        self,
        *,
        topic_key: str,
        state: str,
        source_kind: str,
        state_actor_display_name: str | None,
    ) -> bool:
        """只隐藏历史导入器预置的非完成条目。

        同一 topic 一旦由真实研究员显式写入状态事件，就会重新进入 Dashboard；
        completed 仍由完成决策自动投影，不受此规则影响。
        """

        if state == "completed" or topic_key not in self.system_topic_keys:
            return False
        if source_kind == "automatic":
            return True
        return state_actor_display_name in self.system_actor_names

    @staticmethod
    def normalize_relative_archive_reference(
        current_source_path: str, reference: str
    ) -> tuple[str, str | None, str] | None:
        """解析相对 Archive 文件、目录或受控资源身份。

        返回 ``(path, fragment, kind)``；纯页内锚点、绝对 URL 与站内绝对路径
        不属于 Archive 来源身份，返回 ``None``。所有越界相对路径均显式失败。
        """

        split = urlsplit(reference)
        if (
            split.scheme
            or split.netloc
            or reference.startswith(("/", "\\"))
            or not split.path
        ):
            return None
        path = unquote(split.path).replace("\\", "/")
        normalized = posixpath.normpath(
            posixpath.join(posixpath.dirname(current_source_path), path)
        )
        if normalized in {".", ".."} or normalized.startswith("../"):
            raise ArchivePresentationError(
                f"relative archive link escapes source root: {reference}"
            )
        if path.endswith("/"):
            kind = "directory"
        elif normalized.lower().endswith((".md", ".markdown")):
            kind = "markdown"
        else:
            kind = "asset"
        fragment = unquote(split.fragment).strip() or None
        return normalized.rstrip("/") if kind == "directory" else normalized, fragment, kind

    @staticmethod
    def normalize_relative_markdown_path(
        current_source_path: str, reference: str
    ) -> tuple[str, str | None] | None:
        """把相对 Markdown href 解析为 Archive POSIX 身份与可选 fragment。"""

        normalized = ArchivePresentation.normalize_relative_archive_reference(
            current_source_path, reference
        )
        if normalized is None or normalized[2] != "markdown":
            return None
        return normalized[0], normalized[1]
