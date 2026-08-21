"""Fixed VM entry for idempotent D-root Windows service installation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from typing import Callable, Sequence
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import read_json, write_atomic_new_json

from .vm_boundary import (
    capture_vm_write_snapshot,
    declared_production_vm_write_set,
    finalize_vm_write_audit,
    verify_vm_write_target,
)
from .vm_deploy_cli import WindowsServiceRuntime, verify_production_root, verify_runtime_environment
from .windows_service import (
    PyWin32ServiceInstaller,
    apply_install_candidate,
    build_install_candidate,
)


class VMServiceCLIError(RuntimeError):
    pass


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]]


def production_runtime_document() -> dict[str, object]:
    """Return the one reviewed service topology; it contains no credential."""

    return {
        "schema_version": "qrh-vm-deploy-runtime/v1",
        "service_name": "QuantResearchHub",
        "base_url": "http://127.0.0.1:8765",
        "listen_host": "0.0.0.0",
        "port": 8765,
        "critical_paths": [
            "/login",
            "/api/v1/research",
            "/api/v1/dashboard",
        ],
        "writer_authority": "D-active",
        "write_paths": list(declared_production_vm_write_set().values()),
        "service_entry_relative_path": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
        "application_source_relative_path": "runtime_contract/code/src",
        "archive_root_relative_path": "reference/archive",
        "var_root_relative_path": "runtime",
        "migration_root_relative_path": "runtime_contract/migrations/platform",
        "access_password_digest_path": "state/viewer_access_password.digest",
        "session_key_path": "state/viewer_secret.key",
        "comment_database_path": "state/comments.sqlite3",
        "workspace_database_path": "state/research_workspace.sqlite3",
    }


def apply_runtime_config(root: Path) -> Path:
    path = root / "control" / "deployment_runtime.json"
    verify_vm_write_target(path, allow_root=False, must_exist=False)
    document = production_runtime_document()
    if path.exists() and read_json(path) == document:
        return path.resolve(strict=True)
    if path.exists():
        temporary = path.with_name(".deployment_runtime.json.partial")
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    else:
        write_atomic_new_json(path, document)
    return path.resolve(strict=True)


def verify_protected_service_state(root: Path) -> None:
    digest_path = root / "state" / "viewer_access_password.digest"
    ensure_no_reparse_components(digest_path)
    try:
        digest = digest_path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise VMServiceCLIError("protected access password digest is unavailable") from error
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise VMServiceCLIError("protected access password digest is invalid")
    for name in ("comments.sqlite3", "research_workspace.sqlite3"):
        path = root / "state" / name
        ensure_no_reparse_components(path)
        try:
            connection = sqlite3.connect(
                f"file:{path.resolve(strict=True).as_posix()}?mode=ro", uri=True,
                timeout=10,
            )
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
        except (OSError, sqlite3.Error) as error:
            raise VMServiceCLIError(f"protected {name} is unavailable") from error
        finally:
            if "connection" in locals():
                connection.close()
                del connection
        if integrity is None or integrity[0] != "ok":
            raise VMServiceCLIError(f"protected {name} failed integrity check")


def _runner(arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    # main() has already mechanically verified these inherited paths against
    # exact VM_ROOT; preserve them for sc.exe rather than using system temp.
    return subprocess.run(
        list(arguments), shell=False, check=False, capture_output=True,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": os.environ.get(
                "PYTHONPYCACHEPREFIX", os.environ["TEMP"]
            ),
        },
    )


def stage_python_service_executable(
    root: Path, *, source: Path | None = None
) -> Path:
    expected = (
        root / "tooling" / "python" / "Lib" / "site-packages" / "win32"
        / "pythonservice.exe"
    )
    verify_vm_write_target(expected, allow_root=False, must_exist=True)
    ensure_no_reparse_components(expected)
    resolved = expected.resolve(strict=True)
    if source is not None and source.resolve(strict=True) != resolved:
        raise VMServiceCLIError("service executable must belong to D-root service Python")
    if not resolved.is_file():
        raise VMServiceCLIError("D-root pythonservice.exe is unavailable")
    return resolved


def service_action(
    service_name: str,
    action: str,
    *,
    runner: CommandRunner = _runner,
) -> None:
    if action not in {"start", "stop"}:
        raise VMServiceCLIError("unsupported service action")
    result = runner(("sc.exe", action, service_name))
    if result.returncode:
        raise VMServiceCLIError(f"Windows service {action} failed")


def record_service_control_evidence(
    root: Path,
    *,
    action: str,
    candidate_document: dict[str, object],
    allow_test_root: bool = False,
) -> tuple[Path, str]:
    """Record the sole OS-managed non-file mutation without recording secrets."""

    canonical = json.dumps(
        candidate_document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    candidate_sha256 = hashlib.sha256(canonical).hexdigest()
    evidence_id = f"service-control-{uuid4().hex}"
    path = root / "audit" / "events" / f"{evidence_id}.json"
    if allow_test_root:
        if not path.resolve().is_relative_to(root.resolve(strict=True)):
            raise VMServiceCLIError("test evidence path escaped its fixture root")
    else:
        verify_vm_write_target(path, allow_root=False, must_exist=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_atomic_new_json(
        path,
        {
            "schema_version": "qrh-service-control-evidence/v1",
            "evidence_id": evidence_id,
            "action": action,
            "candidate_sha256": candidate_sha256,
            "service_name": candidate_document["service_name"],
            "image_path": candidate_document["service_executable"],
            "python_class": candidate_document["python_class"],
            "start_type": candidate_document["start_type"],
            "scm_binding_verified": True,
            "os_managed_non_file_state": "windows_scm_service_registration",
            "filesystem_authority_root": r"D:\quant\quant_platform",
            "contains_secret": False,
        },
    )
    return path, candidate_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("apply-install", "start", "stop"))
    parser.add_argument("--vm-root", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root: Path | None = None
    before = None
    service_evidence: Path | None = None
    candidate_sha256: str | None = None
    try:
        root = verify_production_root(args.vm_root)
        verify_runtime_environment(root, os.environ)
        before = capture_vm_write_snapshot(root)
        if args.action == "apply-install":
            apply_runtime_config(root)
            runtime = WindowsServiceRuntime.load(root)
            verify_protected_service_state(root)
            stage_python_service_executable(root)
            candidate = build_install_candidate(root, runtime.service_name)
            performed = apply_install_candidate(
                root, candidate, installer=PyWin32ServiceInstaller()
            )
            service_evidence, candidate_sha256 = record_service_control_evidence(
                root,
                action=performed,
                candidate_document=dict(candidate.document()),
            )
        else:
            runtime = WindowsServiceRuntime.load(root)
            service_action(runtime.service_name, args.action)
            performed = args.action
        finalize_vm_write_audit(
            root, before, operation=f"service-{args.action}", outcome="succeeded"
        )
        result = {
            "schema_version": "qrh-vm-service-result/v1",
            "status": "ok",
            "action": performed,
            "service_name": runtime.service_name,
        }
        if service_evidence is not None and candidate_sha256 is not None:
            result.update(
                {
                    "service_install_candidate_sha256": candidate_sha256,
                    "service_control_evidence_id": service_evidence.stem,
                }
            )
    except Exception as error:
        if root is not None and before is not None:
            try:
                finalize_vm_write_audit(
                    root, before, operation=f"service-{args.action}", outcome="failed"
                )
            except Exception:
                pass
        result = {
            "schema_version": "qrh-vm-service-result/v1",
            "status": "error",
            "error_type": type(error).__name__,
        }
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
