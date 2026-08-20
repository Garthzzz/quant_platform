"""Public Git boundary gate for Quant Research Hub.

The gate only reads files selected by the explicit policy. It never follows
symlinks/reparse points and never prints matched secret values. Runtime data,
research content and recovery artifacts remain outside Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = ROOT / "config" / "git_tracked_policy.json"
FORBIDDEN_SUFFIXES = {
    ".db", ".dump", ".pdf", ".ppt", ".pptx", ".sqlite", ".sqlite3",
    ".xls", ".xlsx", ".zip",
}
FORBIDDEN_NAME_FRAGMENTS = ("credential", "storage_state", "cookie")
SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b", re.I),
    "deepseek_key": re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
}
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}


def canonical(value: str) -> str:
    value = value.replace("\\", "/").removeprefix("./")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return pure.as_posix()


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != "qrh.git-boundary/v1":
        raise ValueError("unsupported Git boundary policy")
    for key in ("tracked_exact", "excluded_exact"):
        policy[key] = sorted({canonical(item) for item in policy[key]})
    for key in ("tracked_prefixes", "excluded_prefixes"):
        policy[key] = sorted({canonical(item).rstrip("/") + "/" for item in policy[key]})
    return policy


def under(path: str, prefixes: Iterable[str]) -> bool:
    return any(path.startswith(prefix) for prefix in prefixes)


def allowed(path: str, policy: dict[str, Any]) -> bool:
    if path in policy["tracked_exact"]:
        return True
    if path in policy["excluded_exact"] or under(path, policy["excluded_prefixes"]):
        return False
    return under(path, policy["tracked_prefixes"])


def _git(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, check=False,
        text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return sorted({canonical(item) for item in result.stdout.split("\0") if item})


def selected_paths(scope: str, policy: dict[str, Any]) -> list[str]:
    if scope == "staged":
        return _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    if scope == "tracked":
        return _git("ls-files", "-z")
    paths = set(policy["tracked_exact"])
    for prefix in policy["tracked_prefixes"]:
        root = ROOT / prefix.rstrip("/")
        if not root.exists() or root.is_symlink():
            continue
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            dirs[:] = [
                name for name in dirs
                if name not in {".git", ".pytest_cache", "__pycache__"}
                and not name.endswith(".egg-info")
                and not (current_path / name).is_symlink()
            ]
            for name in names:
                rel = (current_path / name).relative_to(ROOT).as_posix()
                if allowed(rel, policy):
                    paths.add(rel)
    return sorted(path for path in paths if (ROOT / path).is_file())


def _path_failure(path: str) -> str | None:
    if len(path) > 240:
        return "relative_path_over_240_chars"
    for part in PurePosixPath(path).parts:
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED:
            return "windows_reserved_name"
        if part.endswith((" ", ".")) or any(char in part for char in '<>:"|?*'):
            return "windows_unsafe_component"
    return None


def _is_reparse(path: Path) -> bool:
    current = path
    while current != ROOT:
        if current.is_symlink():
            return True
        try:
            attrs = current.stat(follow_symlinks=False).st_file_attributes
        except (AttributeError, OSError):
            attrs = 0
        if attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            return True
        current = current.parent
    return False


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def gate(paths: list[str], policy: dict[str, Any]) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    total_bytes = 0
    allowed_extensions = set(policy["allowed_extensions"])
    for rel in paths:
        path = ROOT / rel
        if not allowed(rel, policy):
            failures.append({"path": rel, "type": "not_in_public_allowlist"})
            continue
        if not path.is_file():
            failures.append({"path": rel, "type": "missing_or_not_regular"})
            continue
        if _is_reparse(path):
            failures.append({"path": rel, "type": "symlink_or_reparse"})
        unsafe = _path_failure(rel)
        if unsafe:
            failures.append({"path": rel, "type": unsafe})
        lower = rel.lower()
        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_SUFFIXES or lower.endswith((".sqlite-wal", ".sqlite-shm", ".sqlite3-wal", ".sqlite3-shm")):
            failures.append({"path": rel, "type": "forbidden_binary_or_state"})
        if any(fragment in lower for fragment in FORBIDDEN_NAME_FRAGMENTS):
            failures.append({"path": rel, "type": "credential_or_session_filename"})
        if suffix not in allowed_extensions:
            failures.append({"path": rel, "type": "extension_not_allowed", "extension": suffix})
        size = path.stat().st_size
        total_bytes += size
        if size > int(policy["large_file_block_bytes"]):
            failures.append({"path": rel, "type": "large_file_block", "size": size})
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files.append({"path": rel, "size": size, "sha256": f"sha256:{digest}"})
        if size <= 5 * 1024 * 1024 and suffix in {"", ".bat", ".cfg", ".css", ".html", ".ini", ".js", ".json", ".jsonl", ".md", ".ps1", ".py", ".sql", ".toml", ".txt", ".yaml", ".yml"}:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                failures.append({"path": rel, "type": "non_utf8_text"})
                continue
            for kind, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    failures.append({"path": rel, "type": kind, "line": line, "fingerprint": _fingerprint(match.group(0))})
    return {
        "schema_version": "qrh.git-gate/v1",
        "status": "blocked" if failures else "pass",
        "file_count": len(paths),
        "total_bytes": total_bytes,
        "files": files,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("gate", "list"))
    parser.add_argument("--scope", choices=("all", "staged", "tracked"), default="all")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    policy = load_policy(args.policy.resolve())
    paths = selected_paths(args.scope, policy)
    if args.command == "list":
        print("\n".join(paths))
        return 0
    result = gate(paths, policy)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("status", "file_count", "total_bytes", "failures")}, ensure_ascii=False))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
