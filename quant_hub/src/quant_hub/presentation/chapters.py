"""Version-bound Archive reading chapter manifests.

The loader rejects stale or partially changed manifests before request handling.  It
never scans ``reference`` and never derives chapter boundaries in a web request.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


class ArchiveChapterManifestError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _content_seal(value: dict[str, Any], field: str) -> str:
    material = dict(value)
    claimed = str(material.pop(field, ""))
    actual = hashlib.sha256(_canonical(material)).hexdigest()
    if claimed != actual:
        raise ArchiveChapterManifestError(f"{field} does not match content")
    return claimed


@dataclass(frozen=True, slots=True)
class ArchiveChapter:
    chapter_key: str
    chapter_revision_id: str
    route_slug: str
    display_title: str
    group: str
    ordinal: int
    absolute_start: int
    absolute_end: int
    source_slice_sha256: str
    heading_anchor_ids: tuple[str, ...]

    @property
    def bytes(self) -> int:
        return self.absolute_end - self.absolute_start


class ArchiveChapterManifests:
    """Read-only, hash-verified chapter/anchor/relationship projection."""

    def __init__(self, root: Path):
        pointer_path = root / "active.json"
        pointer: dict[str, Any] | None = None
        if pointer_path.exists():
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            if pointer.get("schema_version") != "qrh-archive-chapter-generation-pointer/v1":
                raise ArchiveChapterManifestError("chapter generation pointer is invalid")
            generation_id = str(pointer["generation_id"])
            if not re_full_sha256(generation_id):
                raise ArchiveChapterManifestError("chapter generation ID is invalid")
            generation_directory = str(pointer.get("generation_directory", ""))
            if generation_directory != f"g-{generation_id[:16]}":
                raise ArchiveChapterManifestError("chapter generation directory is invalid")
            expected_generation = hashlib.sha256(
                _canonical(dict(pointer.get("files", {})))
            ).hexdigest()
            if generation_id != expected_generation:
                raise ArchiveChapterManifestError("chapter generation seal is invalid")
            root = root / "generations" / generation_directory
        self.root = root
        self._by_research: dict[str, dict[str, Any]] = {}
        index_path = root / "index.json"
        index_bytes = index_path.read_bytes()
        if pointer is not None and hashlib.sha256(index_bytes).hexdigest() != pointer[
            "index_sha256"
        ]:
            raise ArchiveChapterManifestError("active chapter index does not match pointer")
        index = json.loads(index_bytes.decode("utf-8"))
        if index.get("schema_version") != "qrh-archive-chapter-manifest-index/v1":
            raise ArchiveChapterManifestError("chapter manifest index schema is unsupported")
        _content_seal(index, "manifest_content_sha256")
        evidence_snapshot_sha256 = str(
            index.get("evidence_absolute_span_snapshot_sha256", "")
        )
        if not re_full_sha256(evidence_snapshot_sha256):
            raise ArchiveChapterManifestError("Evidence span snapshot seal is invalid")
        for item in index.get("research", []):
            path = root / str(item["manifest_path"])
            payload = path.read_bytes()
            actual = hashlib.sha256(payload).hexdigest()
            if pointer is not None and actual != pointer["files"].get(path.name):
                raise ArchiveChapterManifestError("active chapter file does not match pointer")
            if actual != item["manifest_file_sha256"]:
                raise ArchiveChapterManifestError(f"chapter manifest hash mismatch: {path.name}")
            manifest = json.loads(payload.decode("utf-8"))
            slug = str(manifest["research_slug"])
            if slug != item["research_slug"] or slug in self._by_research:
                raise ArchiveChapterManifestError("chapter manifest research identity conflicts")
            if manifest.get("manifest_content_sha256") != item["manifest_content_sha256"]:
                raise ArchiveChapterManifestError("chapter manifest content seal mismatch")
            _content_seal(manifest, "manifest_content_sha256")
            if manifest.get("evidence_absolute_span_snapshot_sha256") != item.get(
                "evidence_absolute_span_snapshot_sha256"
            ):
                raise ArchiveChapterManifestError(
                    "chapter Evidence snapshot seal does not match index"
                )
            self._validate_manifest(manifest)
            self._by_research[slug] = manifest
        self.index_sha256 = hashlib.sha256(index_bytes).hexdigest()
        self.manifest_revision = str(index["manifest_revision"])

    @classmethod
    def default(cls) -> "ArchiveChapterManifests":
        return cls(Path(__file__).with_name("chapter_manifests"))

    @staticmethod
    def _validate_manifest(manifest: dict[str, Any]) -> None:
        if manifest.get("schema_version") != "qrh-archive-chapter-manifest/v1":
            raise ArchiveChapterManifestError("chapter manifest schema is unsupported")
        document_keys: set[str] = set()
        for document in manifest.get("documents", []):
            document_key = str(document["document_key"])
            if document_key in document_keys:
                raise ArchiveChapterManifestError("duplicate chapter document key")
            document_keys.add(document_key)
            source_bytes = int(document["source_bytes"])
            chapters = list(document.get("chapters", []))
            if not chapters:
                raise ArchiveChapterManifestError("chapter document is empty")
            previous_end = 0
            chapter_keys: set[str] = set()
            revisions: set[str] = set()
            for ordinal, chapter in enumerate(chapters, start=1):
                start = int(chapter["absolute_start"])
                end = int(chapter["absolute_end"])
                if start != previous_end or not start < end <= source_bytes:
                    raise ArchiveChapterManifestError("chapter ranges are not continuous")
                if int(chapter["ordinal"]) != ordinal:
                    raise ArchiveChapterManifestError("chapter ordinal is not stable")
                key = str(chapter["chapter_key"])
                revision = str(chapter["chapter_revision_id"])
                if key in chapter_keys or revision in revisions:
                    raise ArchiveChapterManifestError("chapter identity is duplicated")
                if not revision.startswith("chr_sha256_"):
                    raise ArchiveChapterManifestError("chapter revision identity is invalid")
                chapter_keys.add(key)
                revisions.add(revision)
                previous_end = end
            if previous_end != source_bytes:
                raise ArchiveChapterManifestError("chapter coverage does not reach EOF")
            span_gate = dict(document.get("absolute_span_gate", {}))
            if not re_full_sha256(
                str(span_gate.get("external_absolute_span_snapshot_sha256", ""))
            ):
                raise ArchiveChapterManifestError(
                    "document Evidence span snapshot seal is invalid"
                )
        revision_ids = {
            str(chapter["chapter_revision_id"])
            for document in manifest.get("documents", [])
            for chapter in document.get("chapters", [])
        }
        chapters_by_revision = {
            str(chapter["chapter_revision_id"]): chapter
            for document in manifest.get("documents", [])
            for chapter in document.get("chapters", [])
        }
        for edge in manifest.get("relationship_edges", []):
            if edge.get("from_document_key") not in document_keys:
                raise ArchiveChapterManifestError("chapter relationship source is missing")
            targets = list(edge.get("targets", []))
            if not targets or any(
                target.get("target_document_key") not in document_keys
                or target.get("target_chapter_revision_id") not in revision_ids
                for target in targets
            ):
                raise ArchiveChapterManifestError("chapter relationship target is missing")
        for edge in manifest.get("pipeline_node_edges", []):
            if (
                edge.get("source_document_key") not in document_keys
                or edge.get("target_document_key") not in document_keys
                or edge.get("target_chapter_revision_id") not in revision_ids
            ):
                raise ArchiveChapterManifestError("pipeline node target is missing")
            target_chapter = chapters_by_revision[
                str(edge["target_chapter_revision_id"])
            ]
            if edge.get("target_anchor_id") not in target_chapter.get(
                "heading_anchor_ids", []
            ):
                raise ArchiveChapterManifestError(
                    "pipeline node anchor is outside its target chapter"
                )
        seen_legacy_routes: set[tuple[str, str]] = set()
        for alias in manifest.get("legacy_chapter_redirects", []):
            identity = (
                str(alias.get("document_key", "")),
                str(alias.get("legacy_route_slug", "")),
            )
            if (
                identity in seen_legacy_routes
                or identity[0] not in document_keys
                or alias.get("target_chapter_revision_id") not in revision_ids
            ):
                raise ArchiveChapterManifestError(
                    "legacy chapter redirect identity or target is invalid"
                )
            seen_legacy_routes.add(identity)
            target_chapter = chapters_by_revision[
                str(alias["target_chapter_revision_id"])
            ]
            if alias.get("target_anchor_id") not in target_chapter.get(
                "heading_anchor_ids", []
            ):
                raise ArchiveChapterManifestError(
                    "legacy chapter redirect anchor is outside its target chapter"
                )

    def manifest(self, research_slug: str) -> dict[str, Any] | None:
        return self._by_research.get(research_slug)

    def release_candidate_sha256(self, research_slug: str) -> str | None:
        manifest = self.manifest(research_slug)
        if manifest is None:
            return None
        return str(
            manifest["archive_release_binding"]["archive_release_candidate_sha256"]
        )

    def document(
        self,
        research_slug: str,
        source_path: str,
        source_sha256: str,
    ) -> dict[str, Any] | None:
        manifest = self.manifest(research_slug)
        if manifest is None:
            return None
        for document in manifest["documents"]:
            if str(document["source_path"]) != source_path:
                continue
            if str(document["source_sha256"]) != source_sha256:
                raise ArchiveChapterManifestError(
                    f"active document does not match sealed chapter source: {source_path}"
                )
            return document
        return None

    def chapters(
        self,
        research_slug: str,
        source_path: str,
        source_sha256: str,
    ) -> tuple[ArchiveChapter, ...]:
        document = self.document(research_slug, source_path, source_sha256)
        if document is None:
            return ()
        rows: list[ArchiveChapter] = []
        for item in document["chapters"]:
            chapter_key = str(item["chapter_key"])
            route_slug = chapter_key.split("/", 1)[-1]
            rows.append(
                ArchiveChapter(
                    chapter_key=chapter_key,
                    chapter_revision_id=str(item["chapter_revision_id"]),
                    route_slug=route_slug,
                    display_title=str(item["display_title"]),
                    group=str(item["group"]),
                    ordinal=int(item["ordinal"]),
                    absolute_start=int(item["absolute_start"]),
                    absolute_end=int(item["absolute_end"]),
                    source_slice_sha256=str(item["source_slice_sha256"]),
                    heading_anchor_ids=tuple(item["heading_anchor_ids"]),
                )
            )
        return tuple(rows)

    def relationships(self, research_slug: str) -> tuple[dict[str, str], ...]:
        manifest = self.manifest(research_slug)
        if manifest is None:
            return ()
        return tuple(dict(item) for item in manifest["relationship_edges"])


__all__ = [
    "ArchiveChapter",
    "ArchiveChapterManifestError",
    "ArchiveChapterManifests",
]


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
