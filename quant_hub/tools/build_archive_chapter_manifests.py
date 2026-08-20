"""构建与 Archive release 和来源 bytes 绑定的语义章节 manifest。

产物只保存来源 byte range、稳定章节身份、原始 heading anchor 与研究关系；
不复制、不规范化、不写回 ``reference/archive`` 正文。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import uuid
from typing import Any

from quant_hub.archive.markdown import HeadingNode, project_markdown


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
DEFAULT_POLICY = FORMAL_ROOT / "fixtures" / "archive_chapters" / "chapter_policy.json"
DEFAULT_ABSOLUTE_SPANS = (
    FORMAL_ROOT / "fixtures" / "archive_chapters" / "evidence_absolute_spans.json"
)
DEFAULT_OUTPUT = FORMAL_ROOT / "src" / "quant_hub" / "presentation" / "chapter_manifests"
ARCHIVE_RELEASE_ROOT = FORMAL_ROOT / "fixtures" / "archive_full" / "generated" / "releases"
EVIDENCE_SPAN_SNAPSHOT_SCHEMA = "qrh-archive-evidence-absolute-span-snapshot/v1"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sealed_payload(payload: dict[str, Any], field: str) -> dict[str, Any]:
    return {**payload, field: _sha(_canonical(payload))}


def _normalized_span_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for source in rows:
        row = dict(source)
        row["absolute_start"] = int(row["absolute_start"])
        row["absolute_end"] = int(row["absolute_end"])
        if row["absolute_start"] < 0 or row["absolute_end"] <= row["absolute_start"]:
            raise ValueError("Evidence absolute span is invalid")
        normalized.append(row)
    normalized.sort(
        key=lambda item: (
            int(item["absolute_start"]),
            int(item["absolute_end"]),
            str(item.get("citation_id", "")),
            str(item.get("raw_marker_sha256", "")),
        )
    )
    if len({_canonical(item) for item in normalized}) != len(normalized):
        raise ValueError("Evidence absolute span snapshot contains duplicate rows")
    return normalized


def _normalize_absolute_span_snapshot(
    value: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], str]:
    """Return exact spans, non-positional counts and a canonical content seal.

    The direct ``sha -> rows`` form remains available to focused tests.  Formal
    releases use the versioned snapshot artifact and verify its self-seal before
    any chapter boundary is accepted.
    """

    if value.get("schema_version") == EVIDENCE_SPAN_SNAPSHOT_SCHEMA:
        claimed = str(value.get("snapshot_content_sha256", ""))
        material = dict(value)
        material.pop("snapshot_content_sha256", None)
        actual = _sha(_canonical(material))
        if claimed != actual:
            raise ValueError("Evidence absolute span snapshot seal is invalid")
        documents = dict(value.get("documents", {}))
        exact = {
            str(source_sha256): _normalized_span_rows(
                list(dict(document).get("absolute_spans", []))
            )
            for source_sha256, document in documents.items()
        }
        non_positional = {
            str(source_sha256): int(
                dict(document).get("non_positional_occurrences", 0)
            )
            for source_sha256, document in documents.items()
        }
        return exact, non_positional, claimed

    exact = {
        str(source_sha256): _normalized_span_rows(list(rows))
        for source_sha256, rows in value.items()
    }
    normalized = {
        "schema_version": "qrh-archive-evidence-absolute-span-map/v1",
        "documents": exact,
    }
    return exact, {source_sha256: 0 for source_sha256 in exact}, _sha(
        _canonical(normalized)
    )


def _load_absolute_span_snapshot(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _snapshot_from_evidence_database(
    database_path: Path,
    source_sha256s: list[str],
) -> dict[str, Any]:
    """Freeze only Q2/Q5 occurrence positions from a selected writable DB."""

    resolved = database_path.resolve()
    connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        documents: dict[str, dict[str, Any]] = {}
        for source_sha256 in sorted(set(source_sha256s)):
            rows = connection.execute(
                """
                SELECT citation_id,locator_kind,byte_start,byte_end,raw_marker_sha256
                FROM citation_occurrence
                WHERE document_sha256=?
                ORDER BY COALESCE(byte_start,-1),COALESCE(byte_end,-1),citation_id
                """,
                (source_sha256,),
            ).fetchall()
            absolute_spans = [
                {
                    "citation_id": str(row["citation_id"]),
                    "locator_kind": str(row["locator_kind"]),
                    "absolute_start": int(row["byte_start"]),
                    "absolute_end": int(row["byte_end"]),
                    "raw_marker_sha256": str(row["raw_marker_sha256"]),
                }
                for row in rows
                if row["byte_start"] is not None and row["byte_end"] is not None
            ]
            documents[source_sha256] = {
                "absolute_spans": _normalized_span_rows(absolute_spans),
                "non_positional_occurrences": sum(
                    row["byte_start"] is None or row["byte_end"] is None
                    for row in rows
                ),
            }
    finally:
        connection.close()
    try:
        database_label = resolved.relative_to(WORKSPACE_ROOT).as_posix()
    except ValueError:
        database_label = resolved.name
    payload = {
        "schema_version": EVIDENCE_SPAN_SNAPSHOT_SCHEMA,
        "source_database": database_label,
        "source_database_sha256": _sha(resolved.read_bytes()),
        "documents": documents,
    }
    return _sealed_payload(payload, "snapshot_content_sha256")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".t-{uuid.uuid4().hex}")
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _release_binding(research_slug: str) -> dict[str, str]:
    path = ARCHIVE_RELEASE_ROOT / f"{research_slug}.json"
    payload = path.read_bytes()
    release = json.loads(payload.decode("utf-8"))
    return {
        "archive_release_key": str(release["release_key"]),
        "archive_release_candidate_sha256": _sha(payload),
    }


def _heading_payload(heading: HeadingNode) -> dict[str, Any]:
    return {
        "anchor_id": heading.anchor_id,
        "absolute_byte_start": heading.byte_start,
        "absolute_byte_end": heading.byte_end,
        "level": heading.level,
        "node_path": heading.node_path,
        "source_heading_sha256": heading.source_sha256,
        "source_title": heading.title_text,
    }


def _chapter_revision_id(
    *,
    release_key: str,
    document_key: str,
    source_sha256: str,
    manifest_revision: str,
    chapter_key: str,
    start: int,
    end: int,
) -> str:
    identity = "\0".join(
        (
            "qrh-chapter-revision/v1",
            release_key,
            document_key,
            source_sha256,
            manifest_revision,
            chapter_key,
            str(start),
            str(end),
        )
    ).encode("utf-8")
    return "chr_sha256_" + _sha(identity)


def _ranges_from_headings(
    source_bytes: bytes,
    headings: tuple[HeadingNode, ...],
    *,
    target_max_bytes: int,
) -> list[tuple[int, int]]:
    starts = {0, *(item.byte_start for item in headings if item.level == 2)}
    primary = sorted(starts)
    primary.append(len(source_bytes))
    refined: set[int] = set(primary)
    for start, end in zip(primary, primary[1:]):
        if end - start <= target_max_bytes:
            continue
        refined.update(
            item.byte_start
            for item in headings
            if start < item.byte_start < end and item.level == 3
        )
    second = sorted(refined)
    for start, end in zip(second, second[1:]):
        if end - start <= target_max_bytes:
            continue
        refined.update(
            item.byte_start
            for item in headings
            if start < item.byte_start < end and item.level == 4
        )
    boundaries = sorted(refined)
    return list(zip(boundaries, boundaries[1:]))


def _chapter_rows(
    *,
    source_bytes: bytes,
    headings: tuple[HeadingNode, ...],
    ranges: list[tuple[int, int]],
    document_key: str,
    source_sha256: str,
    release_key: str,
    manifest_revision: str,
    explicit: list[list[Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    headings_by_start = {item.byte_start: item for item in headings}
    chapters: list[dict[str, Any]] = []
    anchor_index: dict[str, dict[str, Any]] = {}
    semantic_key_occurrences: dict[str, int] = {}
    for ordinal, (start, end) in enumerate(ranges, start=1):
        if explicit is None:
            boundary_heading = headings_by_start.get(start)
            if boundary_heading is None:
                suffix = "introduction"
            else:
                fingerprint = boundary_heading.source_sha256[:16]
                occurrence = semantic_key_occurrences.get(fingerprint, 0) + 1
                semantic_key_occurrences[fingerprint] = occurrence
                suffix = f"heading-{fingerprint}"
                if occurrence > 1:
                    suffix += f"-{occurrence}"
            chapter_key = f"{document_key}/{suffix}"
            group = "正文"
            display_title = (
                "导读"
                if boundary_heading is None
                else boundary_heading.title_text
            )
        else:
            slug, group, display_title, expected_start, expected_end = explicit[ordinal - 1]
            if (start, end) != (int(expected_start), int(expected_end)):
                raise ValueError("explicit chapter range changed during normalization")
            chapter_key = f"{document_key}/{slug}"
        local_headings = tuple(
            item for item in headings if start <= item.byte_start < end
        )
        revision_id = _chapter_revision_id(
            release_key=release_key,
            document_key=document_key,
            source_sha256=source_sha256,
            manifest_revision=manifest_revision,
            chapter_key=chapter_key,
            start=start,
            end=end,
        )
        row = {
            "chapter_key": chapter_key,
            "chapter_revision_id": revision_id,
            "display_title": str(display_title),
            "group": str(group),
            "ordinal": ordinal,
            "absolute_start": start,
            "absolute_end": end,
            "source_slice_sha256": _sha(source_bytes[start:end]),
            "heading_anchor_ids": [item.anchor_id for item in local_headings],
        }
        chapters.append(row)
        for heading in local_headings:
            anchor_index[heading.anchor_id] = {
                **_heading_payload(heading),
                "chapter_key": chapter_key,
                "chapter_revision_id": revision_id,
                "local_anchor": heading.anchor_id,
            }
    if not chapters or chapters[0]["absolute_start"] != 0:
        raise ValueError("chapter coverage must start at zero")
    if chapters[-1]["absolute_end"] != len(source_bytes):
        raise ValueError("chapter coverage must reach source EOF")
    for left, right in zip(chapters, chapters[1:]):
        if left["absolute_end"] != right["absolute_start"]:
            raise ValueError("chapter coverage has a gap or overlap")
    reconstructed = b"".join(
        source_bytes[item["absolute_start"] : item["absolute_end"]]
        for item in chapters
    )
    if reconstructed != source_bytes or _sha(reconstructed) != source_sha256:
        raise ValueError("chapter ranges do not reconstruct immutable source")
    return chapters, anchor_index


def _validate_source_spans(
    source_bytes: bytes,
    chapters: list[dict[str, Any]],
    external_spans: list[dict[str, Any]],
    *,
    non_positional_occurrences: int,
) -> dict[str, Any]:
    source_spans = [
        {
            "kind": "source_citation_marker",
            "absolute_start": match.start(),
            "absolute_end": match.end(),
        }
        for match in re.finditer(rb"\^src:\{cit_[a-z2-7]{52}\}", source_bytes)
    ]
    normalized_external = _normalized_span_rows(external_spans)
    spans = source_spans + normalized_external
    for span in spans:
        start = int(span["absolute_start"])
        end = int(span["absolute_end"])
        matches = [
            chapter
            for chapter in chapters
            if int(chapter["absolute_start"]) <= start
            and end <= int(chapter["absolute_end"])
        ]
        if not 0 <= start < end <= len(source_bytes) or len(matches) != 1:
            raise ValueError("absolute Evidence/^src span crosses a chapter boundary")
        marker_sha256 = span.get("raw_marker_sha256")
        if marker_sha256 is not None and _sha(source_bytes[start:end]) != str(
            marker_sha256
        ):
            raise ValueError("Evidence absolute span does not match source marker SHA")
    return {
        "source_citation_markers": len(source_spans),
        "external_absolute_spans": len(normalized_external),
        "external_non_positional_occurrences": int(non_positional_occurrences),
        "external_absolute_span_snapshot_sha256": _sha(
            _canonical(normalized_external)
        ),
    }


def _sealed_manifest(payload: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    dependency_payload = _canonical(payload)
    sealed = {
        **payload,
        "manifest_content_sha256": _sha(dependency_payload),
    }
    return sealed, _canonical(sealed)


def build(
    policy_path: Path,
    archive_root: Path,
    *,
    absolute_spans: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, bytes]:
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes.decode("utf-8"))
    manifest_revision = str(policy["manifest_revision"])
    split = dict(policy["split_policy"])
    snapshot_value = (
        _load_absolute_span_snapshot(DEFAULT_ABSOLUTE_SPANS)
        if absolute_spans is None
        else absolute_spans
    )
    exact_spans, non_positional_counts, evidence_snapshot_sha256 = (
        _normalize_absolute_span_snapshot(snapshot_value)
    )
    outputs: dict[str, bytes] = {}
    index_rows: list[dict[str, Any]] = []

    for research_slug, research_policy in policy["research"].items():
        binding = _release_binding(research_slug)
        documents_policy = (
            [research_policy]
            if "explicit_chapters" in research_policy
            else list(research_policy["documents"])
        )
        documents: list[dict[str, Any]] = []
        path_anchor_index: dict[str, Any] = {}
        policy_by_document_key: dict[str, dict[str, Any]] = {}
        research_snapshot_material: dict[str, dict[str, Any]] = {}
        legacy_chapter_redirects: list[dict[str, str]] = []
        for document_policy in documents_policy:
            source_path = str(document_policy["source_path"])
            source_bytes = (archive_root / Path(source_path)).read_bytes()
            source_sha256 = _sha(source_bytes)
            expected_sha = str(document_policy["source_sha256"])
            if source_sha256 != expected_sha:
                raise ValueError(f"source changed after chapter review: {source_path}")
            projection = project_markdown(source_bytes)
            explicit = document_policy.get("explicit_chapters")
            if explicit is not None:
                ranges = [(int(row[3]), int(row[4])) for row in explicit]
            else:
                ranges = _ranges_from_headings(
                    source_bytes,
                    projection.headings,
                    target_max_bytes=int(split["target_max_bytes"]),
                )
            chapters, anchor_index = _chapter_rows(
                source_bytes=source_bytes,
                headings=projection.headings,
                ranges=ranges,
                document_key=str(document_policy["document_key"]),
                source_sha256=source_sha256,
                release_key=binding["archive_release_key"],
                manifest_revision=manifest_revision,
                explicit=explicit,
            )
            if explicit is not None:
                legacy_ranges = _ranges_from_headings(
                    source_bytes,
                    projection.headings,
                    target_max_bytes=int(split["target_max_bytes"]),
                )
                headings_by_start = {
                    item.byte_start: item for item in projection.headings
                }
                route_occurrences: dict[str, int] = {}
                for legacy_start, _legacy_end in legacy_ranges:
                    boundary = headings_by_start.get(legacy_start)
                    if boundary is None:
                        legacy_slug = "introduction"
                        target_anchor_id = ""
                    else:
                        fingerprint = boundary.source_sha256[:16]
                        occurrence = route_occurrences.get(fingerprint, 0) + 1
                        route_occurrences[fingerprint] = occurrence
                        legacy_slug = f"heading-{fingerprint}"
                        if occurrence > 1:
                            legacy_slug += f"-{occurrence}"
                        target_anchor_id = boundary.anchor_id
                    target_chapter = next(
                        chapter
                        for chapter in chapters
                        if int(chapter["absolute_start"])
                        <= legacy_start
                        < int(chapter["absolute_end"])
                    )
                    if not target_anchor_id:
                        target_anchor_id = str(
                            target_chapter["heading_anchor_ids"][0]
                            if target_chapter["heading_anchor_ids"]
                            else ""
                        )
                    legacy_chapter_redirects.append(
                        {
                            "document_key": str(document_policy["document_key"]),
                            "legacy_route_slug": legacy_slug,
                            "target_chapter_key": str(target_chapter["chapter_key"]),
                            "target_chapter_revision_id": str(
                                target_chapter["chapter_revision_id"]
                            ),
                            "target_anchor_id": target_anchor_id,
                        }
                    )
            span_gate = _validate_source_spans(
                source_bytes,
                chapters,
                list(exact_spans.get(source_sha256, [])),
                non_positional_occurrences=non_positional_counts.get(
                    source_sha256, 0
                ),
            )
            research_snapshot_material[source_sha256] = {
                "absolute_spans": list(exact_spans.get(source_sha256, [])),
                "non_positional_occurrences": non_positional_counts.get(
                    source_sha256, 0
                ),
            }
            document_key = str(document_policy["document_key"])
            policy_by_document_key[document_key] = document_policy
            documents.append(
                {
                    "document_key": document_key,
                    "display_title": str(
                        document_policy.get("title")
                        or document_policy.get("document_title")
                    ),
                    "source_path": source_path,
                    "source_sha256": source_sha256,
                    "source_bytes": len(source_bytes),
                    "document_revision_id": "docrev_sha256_" + source_sha256,
                    "relationship": str(document_policy["relationship"]),
                    "absolute_span_gate": span_gate,
                    "chapters": chapters,
                }
            )
            path_anchor_index[source_path] = {
                "document_key": document_key,
                "anchors": anchor_index,
            }
        documents_by_key = {str(item["document_key"]): item for item in documents}
        anchors_by_document_key = {
            str(item["document_key"]): list(item["anchors"].values())
            for item in path_anchor_index.values()
        }
        relation_edges: list[dict[str, Any]] = []
        pipeline_node_edges: list[dict[str, str]] = []
        for document_key, document_policy in policy_by_document_key.items():
            target = document_policy.get("target_document_key")
            if target is not None:
                target_key = str(target)
                target_document = documents_by_key.get(target_key)
                if target_document is None:
                    raise ValueError("relationship target document is missing")
                target_titles = list(document_policy.get("target_heading_titles", []))
                targets: list[dict[str, str]] = []
                if target_titles:
                    for title in target_titles:
                        matches = [
                            anchor
                            for anchor in anchors_by_document_key[target_key]
                            if str(anchor["source_title"]) == str(title)
                        ]
                        if len(matches) != 1:
                            raise ValueError(
                                f"relationship heading is not unique: {target_key} / {title}"
                            )
                        match = matches[0]
                        targets.append(
                            {
                                "target_document_key": target_key,
                                "target_chapter_key": str(match["chapter_key"]),
                                "target_chapter_revision_id": str(
                                    match["chapter_revision_id"]
                                ),
                                "target_anchor_id": str(match["anchor_id"]),
                            }
                        )
                else:
                    first = target_document["chapters"][0]
                    targets.append(
                        {
                            "target_document_key": target_key,
                            "target_chapter_key": str(first["chapter_key"]),
                            "target_chapter_revision_id": str(
                                first["chapter_revision_id"]
                            ),
                            "target_anchor_id": str(
                                first["heading_anchor_ids"][0]
                                if first["heading_anchor_ids"]
                                else ""
                            ),
                        }
                    )
                relation_edges.append(
                    {
                        "from_document_key": document_key,
                        "relationship": str(document_policy["relationship"]),
                        "targets": targets,
                    }
                )
            for node in document_policy.get("pipeline_node_edges", []):
                target_key = str(node["target_document_key"])
                target_document = documents_by_key.get(target_key)
                if target_document is None:
                    raise ValueError("pipeline node target document is missing")
                target_title = node.get("target_heading_title")
                if target_title is not None:
                    matches = [
                        anchor
                        for anchor in anchors_by_document_key[target_key]
                        if str(anchor["source_title"]) == str(target_title)
                    ]
                    if len(matches) != 1:
                        raise ValueError(
                            "pipeline node heading is not unique: "
                            f"{target_key} / {target_title}"
                        )
                    match = matches[0]
                    target_chapter_key = str(match["chapter_key"])
                    target_chapter_revision_id = str(match["chapter_revision_id"])
                    target_anchor_id = str(match["anchor_id"])
                else:
                    first = target_document["chapters"][0]
                    target_chapter_key = str(first["chapter_key"])
                    target_chapter_revision_id = str(first["chapter_revision_id"])
                    target_anchor_id = str(
                        first["heading_anchor_ids"][0]
                        if first["heading_anchor_ids"]
                        else ""
                    )
                pipeline_node_edges.append(
                    {
                        "source_document_key": document_key,
                        "node_key": str(node["node_key"]),
                        "target_document_key": target_key,
                        "target_chapter_key": target_chapter_key,
                        "target_chapter_revision_id": target_chapter_revision_id,
                        "target_anchor_id": target_anchor_id,
                    }
                )
        legacy_aliases: list[dict[str, Any]] = []
        for source_alias in research_policy.get("legacy_aliases", []):
            alias = dict(source_alias)
            target_key = alias.get("target_document_key")
            if target_key is not None:
                target_document = documents_by_key.get(str(target_key))
                if target_document is None:
                    raise ValueError("legacy alias target document is missing")
                first = target_document["chapters"][0]
                alias["target_chapter_key"] = first["chapter_key"]
                alias["target_chapter_revision_id"] = first["chapter_revision_id"]
                if alias.get("state") == "versioned_alias" and not alias.get(
                    "source_archive_release_key"
                ):
                    raise ValueError("versioned legacy alias has no source release")
            legacy_aliases.append(alias)
        payload = {
            "schema_version": "qrh-archive-chapter-manifest/v1",
            "research_slug": research_slug,
            "manifest_revision": manifest_revision,
            "policy_sha256": _sha(policy_bytes),
            "archive_release_binding": binding,
            "evidence_absolute_span_snapshot_sha256": _sha(
                _canonical(research_snapshot_material)
            ),
            "documents": documents,
            "relationship_edges": relation_edges,
            "pipeline_node_edges": pipeline_node_edges,
            "legacy_chapter_redirects": legacy_chapter_redirects,
            "path_anchor_index": path_anchor_index,
            "legacy_aliases": legacy_aliases,
            "coverage_gate": "continuous_no_overlap_reconstructs_source_sha256",
        }
        sealed, manifest_bytes = _sealed_manifest(payload)
        relative_path = f"{research_slug}.json"
        outputs[relative_path] = manifest_bytes
        index_rows.append(
            {
                "research_slug": research_slug,
                "manifest_path": relative_path,
                "manifest_file_sha256": _sha(manifest_bytes),
                "manifest_content_sha256": sealed["manifest_content_sha256"],
                "archive_release_candidate_sha256": binding[
                    "archive_release_candidate_sha256"
                ],
                "evidence_absolute_span_snapshot_sha256": sealed[
                    "evidence_absolute_span_snapshot_sha256"
                ],
                "document_count": len(documents),
                "chapter_count": sum(len(row["chapters"]) for row in documents),
            }
        )
    index_payload = {
        "schema_version": "qrh-archive-chapter-manifest-index/v1",
        "manifest_revision": manifest_revision,
        "policy_sha256": _sha(policy_bytes),
        "evidence_absolute_span_snapshot_sha256": evidence_snapshot_sha256,
        "research": sorted(index_rows, key=lambda item: item["research_slug"]),
    }
    _, outputs["index.json"] = _sealed_manifest(index_payload)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument(
        "--archive-root",
        type=Path,
        default=WORKSPACE_ROOT / "reference" / "archive",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--absolute-spans",
        type=Path,
        default=DEFAULT_ABSOLUTE_SPANS,
        help="Canonical Q2/Q5 Evidence absolute-span snapshot artifact.",
    )
    parser.add_argument(
        "--evidence-db",
        type=Path,
        default=None,
        help="Read-only Evidence DB used to refresh --absolute-spans before build.",
    )
    args = parser.parse_args()
    if args.evidence_db is not None:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        source_sha256s: list[str] = []
        for research_policy in policy["research"].values():
            document_policies = (
                [research_policy]
                if "explicit_chapters" in research_policy
                else list(research_policy["documents"])
            )
            source_sha256s.extend(
                str(document["source_sha256"]) for document in document_policies
            )
        snapshot = _snapshot_from_evidence_database(
            args.evidence_db, source_sha256s
        )
        _atomic_write(args.absolute_spans, _canonical(snapshot))
    absolute_spans = _load_absolute_span_snapshot(args.absolute_spans)
    outputs = build(
        args.policy.resolve(),
        args.archive_root.resolve(),
        absolute_spans=absolute_spans,
    )
    file_hashes = {name: _sha(payload) for name, payload in outputs.items()}
    generation_id = _sha(_canonical(file_hashes))
    generations = args.output / "generations"
    generation_directory = f"g-{generation_id[:16]}"
    generation_root = generations / generation_directory
    generations.mkdir(parents=True, exist_ok=True)
    if not generation_root.exists():
        staging = generations / f".s-{uuid.uuid4().hex}"
        staging.mkdir()
        try:
            for relative_path, payload in sorted(outputs.items()):
                _atomic_write(staging / relative_path, payload)
            for relative_path, payload in outputs.items():
                if (staging / relative_path).read_bytes() != payload:
                    raise RuntimeError("chapter manifest staging verification failed")
            os.replace(staging, generation_root)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise
    pointer = _canonical(
        {
            "schema_version": "qrh-archive-chapter-generation-pointer/v1",
            "generation_id": generation_id,
            "generation_directory": generation_directory,
            "index_sha256": file_hashes["index.json"],
            "files": file_hashes,
        }
    )
    # The pointer is the only mutable object and is replaced last. Readers
    # therefore observe either the complete previous generation or the
    # complete verified new generation, never a per-file mixture.
    _atomic_write(args.output / "active.json", pointer)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "generation_id": generation_id,
                "files": sorted(outputs),
                "sha256": file_hashes,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
