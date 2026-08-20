"""只读报告研究修订工作区中相对初始导出的 Markdown 变化。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = PROJECT_ROOT / "研究修订工作区"
MARKER = "<!-- QRH_RESEARCH_REVISION_COPY_V1\n"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def report(workspace: Path) -> dict[str, Any]:
    root = workspace.resolve(strict=True)
    manifest_path = root / "_导出清单.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pages = list(manifest.get("pages", []))
    changed: list[dict[str, str]] = []
    missing: list[str] = []
    invalid: list[dict[str, str]] = []
    expected: set[str] = set()
    for row in pages:
        relative = Path(str(row["workspace_relative_path"]))
        expected.add(relative.as_posix().casefold())
        path = (root / relative).resolve(strict=False)
        if root not in path.parents:
            invalid.append({"path": relative.as_posix(), "reason": "path escaped workspace"})
            continue
        if not path.is_file():
            missing.append(relative.as_posix())
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            invalid.append({"path": relative.as_posix(), "reason": "not valid UTF-8"})
            continue
        if not text.startswith(MARKER) or "-->\n\n" not in text:
            invalid.append(
                {"path": relative.as_posix(), "reason": "revision identity header missing"}
            )
            continue
        header, body = text.split("-->\n\n", 1)
        try:
            identity = json.loads(header.splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            invalid.append(
                {"path": relative.as_posix(), "reason": "revision identity JSON invalid"}
            )
            continue
        if identity.get("page_id") != row.get("page_id"):
            invalid.append({"path": relative.as_posix(), "reason": "page identity changed"})
            continue
        current = digest(body)
        baseline = str(row["exported_markdown_sha256"])
        if current != baseline:
            changed.append(
                {
                    "page_id": str(row["page_id"]),
                    "page_title": str(row["page_title"]),
                    "path": relative.as_posix(),
                    "baseline_sha256": baseline,
                    "current_sha256": current,
                    "frontend_url": str(row["frontend_url"]),
                }
            )
    known_indexes = {"readme.md"}
    for research in manifest.get("research", []):
        known_indexes.add(f"{research['directory']}/README.md".casefold())
    untracked = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.md")
        if path.relative_to(root).as_posix().casefold()
        not in expected | {item.casefold() for item in known_indexes}
    )
    integrity = not missing and not invalid
    return {
        "schema_version": "qrh-research-revision-change-report/v1",
        "status": "CHANGED" if changed or untracked else "CLEAN",
        "integrity_status": "PASS" if integrity else "FAIL",
        "workspace": str(root),
        "baseline_pages": len(pages),
        "changed_page_count": len(changed),
        "missing_page_count": len(missing),
        "invalid_page_count": len(invalid),
        "untracked_markdown_count": len(untracked),
        "changed_pages": changed,
        "missing_pages": missing,
        "invalid_pages": invalid,
        "untracked_markdown": untracked,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args(argv)
    try:
        value = report(args.workspace)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
    if value["integrity_status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
