"""从显式 mapping policy 构建可审核的全量 Archive release manifests。

该工具不发布、不写 Archive 源。既有 curated research 仍由审核过的 mapping policy
决定；没有命中旧分组的正常新 Markdown 走统一 default-publishable policy，并明确
handoff 给 deterministic generic compiler。异常/隔离项没有显式处理时仍 fail closed。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from quant_hub.archive.source_reader import ReadOnlyArchiveSource
from quant_hub.knowledge.policy import SourcePolicy


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
DEFAULT_POLICY = FORMAL_ROOT / "fixtures" / "archive_full" / "mapping_policy.json"
DEFAULT_OUTPUT = FORMAL_ROOT / "fixtures" / "archive_full" / "generated"


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def markdown_paths(root: Path) -> list[str]:
    rows: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in {".md", ".markdown"}:
            continue
        rows.append(path.relative_to(root).as_posix())
    return sorted(rows, key=lambda value: (value.casefold(), value))


def matches(group: dict[str, Any], relative_path: str) -> bool:
    exact = set(group.get("exact", []))
    prefix = group.get("prefix")
    selected = relative_path in exact or (
        isinstance(prefix, str) and relative_path.startswith(prefix)
    )
    if not selected:
        return False
    if relative_path in set(group.get("exclude_exact", [])):
        return False
    return not any(
        relative_path.startswith(value) for value in group.get("exclude_prefixes", [])
    )


def excluded_by(group: dict[str, Any], relative_path: str) -> str | None:
    if relative_path in set(group.get("exclude_exact", [])):
        return relative_path
    for prefix in group.get("exclude_prefixes", []):
        if relative_path.startswith(prefix):
            return prefix
    return None


def document_slug(group: dict[str, Any], relative_path: str) -> str:
    override = group.get("document_slug_overrides", {}).get(relative_path)
    if override:
        return str(override)
    digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:16]
    return f"doc-{digest}"


def build(policy_path: Path, archive_root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes.decode("utf-8"))
    reader = ReadOnlyArchiveSource(archive_root)
    all_markdown = markdown_paths(reader.root)
    groups = list(policy["groups"])
    authority = str(policy["mapping_authority_urn"])
    assignments: dict[str, str] = {}
    excluded: list[dict[str, str]] = []
    generic_documents: list[dict[str, Any]] = []
    release_files: dict[str, bytes] = {}
    group_index: list[dict[str, Any]] = []

    for group in groups:
        selected = [path for path in all_markdown if matches(group, path)]
        primary = str(group["primary_path"])
        if primary not in selected:
            raise ValueError(f"primary path is not selected: {primary}")
        for relative_path in selected:
            previous = assignments.setdefault(relative_path, str(group["research_slug"]))
            if previous != group["research_slug"]:
                raise ValueError(f"Markdown assigned to multiple groups: {relative_path}")

        ordered = [primary] + [path for path in selected if path != primary]
        documents: list[dict[str, Any]] = []
        for ordinal, relative_path in enumerate(ordered, start=1):
            snapshot = reader.snapshot(relative_path)
            document_role = str(
                group.get("document_role_overrides", {}).get(
                    relative_path,
                    "primary"
                    if relative_path == primary
                    else group.get("document_role", "chapter"),
                )
            )
            navigation_role = str(
                group.get("navigation_role_overrides", {}).get(
                    relative_path,
                    "primary"
                    if relative_path == primary
                    else "historical"
                    if document_role == "historical"
                    else "section",
                )
            )
            mapping_authority = str(
                group.get("mapping_authority_overrides", {}).get(
                    relative_path, authority
                )
            )
            mapping_note = str(
                group.get("mapping_note_overrides", {}).get(
                    relative_path,
                    "archive-full-mapping-v1 对该 source→research/document 的显式"
                    f"候选映射：{relative_path}；目录只提供线索，最终以冻结审核包为准。",
                )
            )
            documents.append(
                {
                    "document_slug": document_slug(group, relative_path),
                    "document_role": document_role,
                    "source_path": relative_path,
                    "approved_origin_uri": snapshot.origin_uri,
                    "approved_object_urn": f"qrh:object:obj_sha256_{snapshot.sha256}",
                    "approved_content_sha256": snapshot.sha256,
                    "approved_bytes": snapshot.bytes,
                    "navigation_role": navigation_role,
                    "sort_key": ordinal * 10,
                    "mapping_authority_urn": mapping_authority,
                    "mapping_note": mapping_note,
                }
            )

        version_relations: list[dict[str, str]] = []
        if group["research_slug"] == "q2-low-snr-neural-selection-factory":
            version_relations.append(
                {
                    "document_slug": "literature-review",
                    "from_content_sha256": "e68a63a1883c24cf48de6d4b3f0a9030689feced99e02ea4ed9f33144ed4dc7a",
                    "to_content_sha256": "5b2e4fcb3bfbe8024df59fcd9370ed641fa8919cfce1ffea7493e1f6a7a8fd03",
                    "relation_kind": "derived_from",
                    "status": "verified",
                    # Relation provenance is the immutable first-review evidence,
                    # not the current presentation path.  The same e68 source bytes
                    # were later renamed; retaining this historical URN lets an old
                    # reviewed database replay the current 12-document Q2 release
                    # without rewriting an already certified lineage assertion.
                    "provenance_urn": "archive:///Q2_%E5%A6%82%E4%BD%95%E9%80%A0%E4%B8%80%E4%B8%AA%E5%A5%BD%E7%9A%84%E5%B7%A5%E5%8E%82/RESEARCH_LITREVIEW_AND_ANALYSIS_DETAILED.md#line:6",
                }
            )
        release = {
            "research_slug": group["research_slug"],
            "display_title": group["display_title"],
            "release_key": group["release_key"],
            "documents": documents,
            "version_relations": version_relations,
            "summary": group.get("summary"),
            "summary_provenance_urn": (
                documents[0]["approved_object_urn"] if group.get("summary") else None
            ),
            "activate": False,
            "release_snapshot_urn": None,
            "activation_decision_hash": None,
        }
        relative_output = f"releases/{group['research_slug']}.json"
        release_payload = canonical_json(release).encode("utf-8")
        release_files[relative_output] = release_payload
        group_index.append(
            {
                "research_slug": group["research_slug"],
                "display_title": group["display_title"],
                "release_file": relative_output,
                "release_sha256": hashlib.sha256(release_payload).hexdigest(),
                "document_count": len(documents),
                "work_state_hint": group["work_state_hint"],
                "work_state_reason": group["work_state_reason"],
                "dashboard_topic_key": group.get("dashboard_topic_key"),
                "dashboard_order": group.get("dashboard_order"),
            }
        )

    reasons = dict(policy.get("exclusion_reasons", {}))
    for relative_path in all_markdown:
        if relative_path in assignments:
            continue
        matched_reason: str | None = None
        matched_group: str | None = None
        for group in groups:
            key = excluded_by(group, relative_path)
            if key is not None:
                matched_reason = reasons.get(key)
                matched_group = str(group["research_slug"])
                break
        if not matched_reason:
            snapshot = reader.snapshot(relative_path)
            decision = SourcePolicy().evaluate(relative_path, snapshot.content)
            if decision.publishable:
                generic_documents.append(
                    {
                        "path": relative_path,
                        "bytes": snapshot.bytes,
                        "sha256": snapshot.sha256,
                        "source_class": decision.source_class,
                        "policy_version": SourcePolicy().config.policy_version,
                        "external_ai_allowed": decision.external_ai_allowed,
                        "handoff": "deterministic_reference_compiler",
                    }
                )
                continue
            raise ValueError(
                "unassigned Markdown is not default-publishable and has no explicit "
                f"quarantine/exclusion handling: {relative_path} ({decision.reason_code})"
            )
        excluded.append(
            {
                "path": relative_path,
                "candidate_research_slug": matched_group or "",
                "reason": matched_reason,
            }
        )

    source_rows = []
    for relative_path in all_markdown:
        snapshot = reader.snapshot(relative_path)
        source_rows.append((relative_path, snapshot.bytes, snapshot.sha256))
    source_manifest = "\n".join(
        f"{path}\t{size}\t{digest}" for path, size, digest in source_rows
    ).encode("utf-8")
    bootstrap_releases: list[dict[str, Any]] = []
    for item in policy.get("bootstrap_releases", []):
        path = WORKSPACE_ROOT / str(item["path"])
        payload = path.read_bytes()
        # The builder deliberately does not import the Pydantic contract here;
        # generated fixtures are validated by the formal test suite.  It still
        # freezes every bootstrap byte and purpose in the candidate index.
        bootstrap_releases.append(
            {
                "path": str(item["path"]),
                "research_slug": str(item["research_slug"]),
                "release_key": str(item["release_key"]),
                "reason": str(item["reason"]),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    index = {
        "schema_version": "qrh-archive-full-mapping-candidate/v1",
        "status": "READY_FOR_INDEPENDENT_MAPPING_REVIEW",
        "policy_path": policy_path.relative_to(WORKSPACE_ROOT).as_posix(),
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "mapping_authority_urn": authority,
        "source": {
            "markdown_count": len(all_markdown),
            "markdown_bytes": sum(row[1] for row in source_rows),
            "manifest_sha256": hashlib.sha256(source_manifest).hexdigest(),
        },
        "coverage": {
            "assigned_count": len(assignments),
            "generic_count": len(generic_documents),
            "excluded_count": len(excluded),
            "unassigned_count": 0,
            "multiply_assigned_count": 0,
        },
        "groups": group_index,
        "bootstrap_releases": bootstrap_releases,
        "excluded": excluded,
        "generic_documents": generic_documents,
    }
    release_files["index.json"] = canonical_json(index).encode("utf-8")
    release_files["source_manifest.tsv"] = source_manifest + b"\n"
    return index, release_files


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--archive-root", type=Path, default=WORKSPACE_ROOT / "reference" / "archive")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    index, files = build(args.policy.resolve(), args.archive_root.resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    for relative_path, payload in sorted(files.items()):
        target = args.output / relative_path
        if target.exists():
            existing = target.read_bytes()
            if existing == payload:
                continue
            target.unlink()
        atomic_write(target, payload)
    print(canonical_json(index), end="")


if __name__ == "__main__":
    main()
