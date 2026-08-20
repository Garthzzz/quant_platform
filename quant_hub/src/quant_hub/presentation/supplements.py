"""Hash-bound reader pages derived from reviewed internal experiment material.

Archive Markdown remains immutable and authoritative.  Supplements are a
separate presentation layer: they may synthesize experiment tables and
figures, but each published page is bound to an exact UTF-8 resource and is
never inserted into the Archive source/release tables.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from quant_hub.archive.markdown import project_markdown


class ResearchSupplementError(RuntimeError):
    pass


_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{2,79}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SupplementalResearchDocuments:
    """Load a closed, hash-bound set of reader-facing research supplements."""

    SCHEMA_VERSION = "qrh-research-supplements/v1"

    def __init__(self, manifest_path: Path):
        self.manifest_path = manifest_path.resolve(strict=True)
        self.resource_root = self.manifest_path.parent.resolve(strict=True)
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != self.SCHEMA_VERSION:
            raise ResearchSupplementError("research supplement schema is unsupported")
        rows = payload.get("documents")
        if not isinstance(rows, list) or not rows:
            raise ResearchSupplementError("research supplement manifest is empty")
        self._documents: dict[str, dict[str, Any]] = {}
        self._by_research: dict[str, list[dict[str, Any]]] = {}
        self._by_workspace_path: dict[str, dict[str, Any]] = {}
        for position, raw in enumerate(rows):
            if not isinstance(raw, dict):
                raise ResearchSupplementError("research supplement row must be an object")
            document = self._validate_document(raw, position)
            supplement_id = str(document["supplement_id"])
            if supplement_id in self._documents:
                raise ResearchSupplementError("duplicate research supplement identity")
            workspace_key = str(document["workspace_relative_path"]).casefold()
            if workspace_key in self._by_workspace_path:
                raise ResearchSupplementError(
                    "duplicate research supplement workspace path"
                )
            self._documents[supplement_id] = document
            self._by_workspace_path[workspace_key] = document
            self._by_research.setdefault(str(document["research_slug"]), []).append(
                document
            )
        for research_rows in self._by_research.values():
            research_rows.sort(key=lambda item: (int(item["sort_key"]), item["supplement_id"]))

    @classmethod
    def default(cls) -> "SupplementalResearchDocuments":
        return cls(Path(__file__).with_name("research_supplements.json"))

    def _validate_document(
        self, raw: dict[str, Any], position: int
    ) -> dict[str, Any]:
        field = f"documents[{position}]"
        supplement_id = str(raw.get("supplement_id", ""))
        research_slug = str(raw.get("research_slug", ""))
        document_key = str(raw.get("document_key", ""))
        if not all(
            _IDENTIFIER.fullmatch(value)
            for value in (supplement_id, research_slug, document_key)
        ):
            raise ResearchSupplementError(f"{field} has an invalid identity")
        title = raw.get("display_title")
        group_title = raw.get("group_title")
        if not isinstance(title, str) or not title.strip():
            raise ResearchSupplementError(f"{field} has no display title")
        if not isinstance(group_title, str) or not group_title.strip():
            raise ResearchSupplementError(f"{field} has no group title")
        workspace_relative = PurePosixPath(
            str(raw.get("workspace_relative_path", "")).replace("\\", "/")
        )
        if (
            workspace_relative.is_absolute()
            or not workspace_relative.parts
            or any(part in {"", ".", ".."} for part in workspace_relative.parts)
            or workspace_relative.suffix.lower() not in {".md", ".markdown"}
        ):
            raise ResearchSupplementError(
                f"{field} workspace path is invalid"
            )
        relative = PurePosixPath(str(raw.get("resource", "")))
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.suffix.lower() not in {".md", ".markdown"}
        ):
            raise ResearchSupplementError(f"{field} resource path is invalid")
        resource = (self.resource_root / Path(*relative.parts)).resolve(strict=True)
        if not resource.is_relative_to(self.resource_root) or not resource.is_file():
            raise ResearchSupplementError(f"{field} resource escaped its root")
        source_bytes = resource.read_bytes()
        try:
            source_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ResearchSupplementError(f"{field} is not UTF-8") from error
        expected_sha = str(raw.get("sha256", "")).lower()
        expected_bytes = raw.get("bytes")
        if not _SHA256.fullmatch(expected_sha):
            raise ResearchSupplementError(f"{field} has an invalid SHA-256")
        if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool):
            raise ResearchSupplementError(f"{field} has an invalid byte count")
        actual_sha = hashlib.sha256(source_bytes).hexdigest()
        if (actual_sha, len(source_bytes)) != (expected_sha, expected_bytes):
            raise ResearchSupplementError(f"{field} resource identity changed")
        projection = project_markdown(source_bytes)
        return {
            **raw,
            "display_title": title.strip(),
            "group_title": group_title.strip(),
            "workspace_relative_path": workspace_relative.as_posix(),
            "resource_path": resource,
            "source_bytes": source_bytes,
            "projection": projection,
        }

    @staticmethod
    def _toc(nodes: tuple[Any, ...]) -> list[dict[str, Any]]:
        return [
            {
                **asdict(node),
                "children": SupplementalResearchDocuments._toc(node.children),
            }
            for node in nodes
        ]

    def documents_for(
        self, research_slug: str, research_id: str
    ) -> list[dict[str, Any]]:
        return [
            self._frontend_document(item, research_id)
            for item in self._by_research.get(research_slug, [])
        ]

    def document_for(
        self, research_slug: str, research_id: str, supplement_id: str
    ) -> dict[str, Any] | None:
        item = self._documents.get(supplement_id)
        if item is None or item["research_slug"] != research_slug:
            return None
        return self._frontend_document(item, research_id, include_source=True)

    def source_bytes(self, research_slug: str, supplement_id: str) -> bytes | None:
        item = self._documents.get(supplement_id)
        if item is None or item["research_slug"] != research_slug:
            return None
        return bytes(item["source_bytes"])

    def workspace_page_bindings(
        self, research_ids_by_slug: dict[str, str]
    ) -> dict[str, tuple[str, None, str]]:
        """Map managed Markdown paths to their reviewed supplemental reader pages."""

        bindings: dict[str, tuple[str, None, str]] = {}
        for item in self._documents.values():
            research_id = research_ids_by_slug.get(str(item["research_slug"]))
            if research_id is None:
                continue
            relative = str(item["workspace_relative_path"])
            bindings[relative.casefold()] = (
                research_id,
                None,
                f"/research/{research_id}/supplements/{item['supplement_id']}",
            )
        return bindings

    def link_workspace_updates(
        self,
        updates: list[dict[str, Any]],
        research_ids_by_slug: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Resolve editable-workspace events to their published supplement pages."""

        linked: list[dict[str, Any]] = []
        for update in updates:
            workspace_path = str(
                update.get("source_relative_path", "")
            ).replace("\\", "/")
            workspace_key = workspace_path.casefold().rstrip("/")
            item = self._by_workspace_path.get(workspace_key)
            current_page_url = str(update.get("page_url", ""))
            if item is None and not current_page_url.startswith("/research/"):
                descendant_prefix = workspace_key + "/"
                descendants = {
                    str(candidate["supplement_id"]): candidate
                    for path_key, candidate in self._by_workspace_path.items()
                    if path_key.startswith(descendant_prefix)
                }
                if descendants:
                    item = min(
                        descendants.values(),
                        key=lambda candidate: (
                            int(candidate["sort_key"]),
                            str(candidate["supplement_id"]),
                        ),
                    )
            if item is None:
                linked.append(
                    {
                        **update,
                        "has_published_page": current_page_url.startswith(
                            "/research/"
                        ),
                    }
                )
                continue
            research_id = research_ids_by_slug.get(str(item["research_slug"]))
            if not research_id:
                linked.append(
                    {
                        **update,
                        "has_published_page": current_page_url.startswith(
                            "/research/"
                        ),
                    }
                )
                continue
            supplement_id = str(item["supplement_id"])
            linked.append(
                {
                    **update,
                    "page_url": (
                        f"/research/{research_id}/supplements/{supplement_id}"
                    ),
                    "has_published_page": True,
                }
            )
        return linked

    def _frontend_document(
        self,
        item: dict[str, Any],
        research_id: str,
        *,
        include_source: bool = False,
    ) -> dict[str, Any]:
        supplement_id = str(item["supplement_id"])
        projection = item["projection"]
        document_id = f"supp_{supplement_id}"
        page_url = f"/research/{research_id}/supplements/{supplement_id}"
        row: dict[str, Any] = {
            "document_id": document_id,
            "document_version_id": f"suppver_sha256_{item['sha256']}",
            "slug": supplement_id,
            "document_role": "experiment_evidence",
            "navigation_role": "supplement",
            "content_sha256": str(item["sha256"]),
            "bytes": int(item["bytes"]),
            "source_path": f"supplement://{item['resource']}",
            "display_title": str(item["display_title"]),
            "document_key": str(item["document_key"]),
            "relationship": "validates",
            "page_url": page_url,
            "source_url": page_url + "/source",
            "toc": self._toc(projection.toc),
            "sections": [asdict(node) for node in projection.headings],
            "rendered_html": projection.rendered_html if include_source else "",
            "chapters": [],
            "chapter_groups": [],
            "is_chaptered": False,
            "is_supplement": True,
            "supplement_id": supplement_id,
            "group_title": str(item["group_title"]),
        }
        return row


__all__ = ["ResearchSupplementError", "SupplementalResearchDocuments"]
