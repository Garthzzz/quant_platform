"""Freeze and verify a complete per-file inventory for a legacy release ZIP.

The inventory is content-addressed and deterministic: it contains no local
absolute path and no observation time.  It is suitable as bootstrap evidence,
but it is not itself a release pointer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


SCHEMA_VERSION = "qrh.legacy-zip-inventory/v1"
CHUNK_BYTES = 1024 * 1024
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}


class InventoryError(RuntimeError):
    """The ZIP cannot be a safe, content-addressed release source."""


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK_BYTES):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256_stream(stream)


def safe_member_name(raw: str) -> str:
    name = raw.replace("\\", "/")
    pure = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InventoryError(f"unsafe ZIP member path: {raw!r}")
    for part in pure.parts:
        stem = part.rstrip(" .").split(".", 1)[0].upper()
        if not part or part != part.rstrip(" .") or stem in WINDOWS_RESERVED:
            raise InventoryError(f"Windows-unsafe ZIP member path: {raw!r}")
    return pure.as_posix()


def category(path: str) -> str:
    lowered = path.casefold()
    if "/persistent_seed/" in lowered:
        return "state_seed"
    if lowered.endswith(".sqlite3") and "/runtime/db/" in lowered:
        return "readonly_database"
    if "/runtime/objects/" in lowered:
        return "object"
    if "/runtime/research_papers/" in lowered:
        return "research_paper"
    if "/runtime/paper_lab/" in lowered or "/quant_hub/paper_lab/papers/" in lowered:
        return "paper_lab"
    if "/templates/" in lowered:
        return "template"
    if "/static/" in lowered or lowered.endswith((".css", ".js")):
        return "static"
    if "/runtime_contract/" in lowered or lowered.endswith((".py", ".bat", ".ps1")):
        return "application"
    return "resource"


def _embedded_manifest(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo]) -> dict[str, Any]:
    names = [name for name in members if name.endswith("/deployment_manifest.json")]
    if len(names) != 1:
        raise InventoryError("ZIP must contain exactly one deployment_manifest.json")
    with archive.open(members[names[0]], "r") as stream:
        try:
            value = json.load(stream)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise InventoryError("deployment manifest is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise InventoryError("deployment manifest must be an object")
    return value


def freeze_zip(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    files: list[dict[str, Any]] = []
    category_totals: dict[str, dict[str, int]] = defaultdict(
        lambda: {"files": 0, "bytes": 0}
    )
    with zipfile.ZipFile(path, "r") as archive:
        members: dict[str, zipfile.ZipInfo] = {}
        windows_names: set[str] = set()
        for info in archive.infolist():
            name = safe_member_name(info.filename.rstrip("/"))
            if info.is_dir():
                continue
            folded = name.casefold()
            if folded in windows_names:
                raise InventoryError(f"duplicate/case-colliding ZIP member: {name}")
            windows_names.add(folded)
            if info.flag_bits & 0x1:
                raise InventoryError(f"encrypted ZIP member is not allowed: {name}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                raise InventoryError(f"symbolic-link ZIP member is not allowed: {name}")
            members[name] = info

        manifest = _embedded_manifest(archive, members)
        for name in sorted(members):
            info = members[name]
            with archive.open(info, "r") as stream:
                digest = sha256_stream(stream)
            kind = category(name)
            files.append(
                {
                    "path": name,
                    "bytes": info.file_size,
                    "sha256": digest,
                    "category": kind,
                }
            )
            category_totals[kind]["files"] += 1
            category_totals[kind]["bytes"] += info.file_size

    by_path = {item["path"]: item for item in files}
    for database_name, expected in dict(manifest.get("databases", {})).items():
        suffix = f"/runtime/db/{database_name}".casefold()
        matches = [item for key, item in by_path.items() if key.casefold().endswith(suffix)]
        if len(matches) != 1:
            raise InventoryError(f"declared database is missing or ambiguous: {database_name}")
        item = matches[0]
        if item["sha256"] != expected.get("sha256") or item["bytes"] != expected.get("bytes"):
            raise InventoryError(f"declared database identity mismatch: {database_name}")

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "package": {
            "filename": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256_path(path),
        },
        "deployment": {
            "schema_version": manifest.get("schema_version"),
            "deployment_id": manifest.get("deployment_id"),
            "package_revision": manifest.get("package_revision"),
            "source_delivery": manifest.get("source_delivery"),
            "embedded_manifest_sha256": next(
                item["sha256"]
                for item in files
                if item["path"].endswith("/deployment_manifest.json")
            ),
        },
        "summary": {
            "files": len(files),
            "uncompressed_bytes": sum(item["bytes"] for item in files),
            "categories": dict(sorted(category_totals.items())),
        },
        "files": files,
    }
    payload["inventory_sha256"] = hashlib.sha256(canonical_json(payload)).hexdigest()
    return payload


def verify_inventory(path: Path, inventory_path: Path) -> dict[str, Any]:
    expected = json.loads(inventory_path.read_text(encoding="utf-8"))
    actual = freeze_zip(path)
    if expected != actual:
        raise InventoryError("frozen inventory does not match ZIP bytes")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("zip", type=Path)
    freeze.add_argument("--output", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("zip", type=Path)
    verify.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        payload = freeze_zip(args.zip)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(payload))
    else:
        payload = verify_inventory(args.zip, args.inventory)
    print(
        json.dumps(
            {
                "status": "pass",
                "inventory_sha256": payload["inventory_sha256"],
                "files": payload["summary"]["files"],
                "bytes": payload["summary"]["uncompressed_bytes"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
