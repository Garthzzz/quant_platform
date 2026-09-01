#!/usr/bin/env python3
"""Serve exactly one active immutable release with all mutable paths external."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import secrets
import socket
import stat
import sys
from typing import Any, Mapping

sys.dont_write_bytecode = True
PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
RUNTIME_SCHEMA = "qrh-vm-deploy-runtime/v1"


class ServiceEntryError(RuntimeError):
    pass


def _reject_test_root_on_production_vm(path: Path) -> None:
    """Keep the minimal copied service entry independent and fail before I/O."""

    candidates = [PureWindowsPath(os.path.normpath(str(path)))]
    try:
        candidates.append(
            PureWindowsPath(os.path.normpath(str(path.resolve(strict=False))))
        )
    except OSError:
        pass
    for candidate in candidates:
        try:
            candidate.relative_to(PRODUCTION_ROOT)
        except ValueError:
            continue
        raise ServiceEntryError(
            "test-only service root cannot target production D root or a descendant/alias"
        )


def _canonical_hash(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _json(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ServiceEntryError(f"cannot read reviewed service identity: {path.name}") from error
    if not isinstance(value, dict):
        raise ServiceEntryError(f"reviewed service identity is not an object: {path.name}")
    return value


def _regular(path: Path, *, directory: bool = False) -> Path:
    resolved = path.resolve(strict=True)
    current = resolved
    while True:
        info = current.lstat()
        reparse = stat.S_ISLNK(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0) & 0x400
        )
        if reparse:
            raise ServiceEntryError(f"service path contains a reparse component: {current}")
        if current.parent == current:
            break
        current = current.parent
    info = resolved.lstat()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ServiceEntryError(f"required service directory is unavailable: {resolved}")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ServiceEntryError(f"required service file is unsafe: {resolved}")
    return resolved


def _inside(root: Path, relative: object, label: str, *, directory: bool) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ServiceEntryError(f"{label} is invalid")
    parts = Path(relative).parts
    if Path(relative).is_absolute() or ".." in parts:
        raise ServiceEntryError(f"{label} escapes active release")
    target = _regular(root.joinpath(*parts), directory=directory)
    if not target.is_relative_to(root):
        raise ServiceEntryError(f"{label} escapes active release")
    return target


def _protected_file(path: Path, *, create: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _regular(path.parent, directory=True)
    if create and not path.exists():
        value = secrets.token_hex(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write(value + "\n")
    return _regular(path)


def _secret_key(path: Path) -> str:
    value = _protected_file(path, create=True).read_text(encoding="ascii").strip()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ServiceEntryError("protected Flask session key is invalid")
    return value


def resolve_context(
    vm_root: Path,
    *,
    expected_release_id: str,
    expected_manifest_sha256: str,
    allow_test_root: bool = False,
    candidate_probe: bool = False,
    candidate_release_root: Path | None = None,
) -> tuple[Path, Mapping[str, object], Mapping[str, object], Mapping[str, object]]:
    if allow_test_root:
        _reject_test_root_on_production_vm(vm_root)
    root = _regular(vm_root, directory=True)
    if not allow_test_root and PureWindowsPath(str(root)) != PRODUCTION_ROOT:
        raise ServiceEntryError(r"service root must be exactly D:\quant\quant_platform")
    if candidate_probe:
        if candidate_release_root is None:
            raise ServiceEntryError("candidate release root is required")
        release = _regular(candidate_release_root, directory=True)
        finalized = root / "releases" / expected_release_id
        incoming = root / "incoming" / f"{expected_release_id}.partial"
        if release not in {
            finalized.resolve(strict=False),
            incoming.resolve(strict=False),
        }:
            raise ServiceEntryError(
                "candidate release root is outside exact finalized/incoming paths"
            )
        # Evidence-only candidate probing deliberately does not read, write, or
        # impersonate the production active pointer.
        active: Mapping[str, object] = {
            "schema_version": "qrh-candidate-probe-context/v1",
            "release_id": expected_release_id,
            "release_path": str(release),
            "manifest_sha256": expected_manifest_sha256,
        }
    else:
        if candidate_release_root is not None:
            raise ServiceEntryError(
                "ordinary service cannot carry a candidate release root"
            )
        release = _regular(root / "releases" / expected_release_id, directory=True)
        active = _json(_regular(root / "control" / "active_release.json"))
        if set(active) != {"schema_version", "release_id", "release_path", "manifest_sha256"}:
            raise ServiceEntryError("active pointer schema is not closed")
        if (
            active.get("schema_version") != "qrh-active-release/v1"
            or active.get("release_id") != expected_release_id
            or active.get("manifest_sha256") != expected_manifest_sha256
        ):
            raise ServiceEntryError("active pointer differs from service start authorization")
        if Path(str(active["release_path"])).resolve(strict=True) != release:
            raise ServiceEntryError("active pointer release path is not canonical")
    manifest = _json(_regular(release / "release_manifest.json"))
    if manifest.get("release_id") != expected_release_id or _canonical_hash(manifest) != expected_manifest_sha256:
        raise ServiceEntryError("active release manifest identity differs")
    content = manifest.get("content")
    if not isinstance(content, dict) or not isinstance(content.get("snapshot_id"), str):
        raise ServiceEntryError("active release snapshot identity is missing")
    runtime = _json(_regular(root / "control" / "deployment_runtime.json"))
    return release, active, manifest, runtime


def _trusted_origins(port: int) -> tuple[str, ...]:
    hosts = {"localhost", "127.0.0.1"}
    for value in (socket.gethostname(), socket.getfqdn()):
        if value:
            hosts.add(value)
    try:
        hosts.update(
            item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        )
    except socket.gaierror:
        pass
    configured = os.environ.get("VIEWER_PUBLIC_ORIGINS", "")
    origins = {f"http://{host}:{port}" for host in hosts}
    origins.update(item.strip() for item in configured.split(";") if item.strip())
    return tuple(sorted(origins))


def _generic_release_root(
    release: Path, manifest: Mapping[str, object]
) -> Path | None:
    """Keep the byte-exact V39 renderer separate from generic research.

    The frozen V39 manifest predates the generic artifact contract. It has
    compatibility hashes named ``ir_sha256``/``knowledge_sha256``, but it does
    not contain the generic source-object closure. Treating those legacy fields
    as generic artifacts makes a valid V39 candidate fail before it can serve
    its unchanged frontend.
    """

    application = manifest.get("application")
    if not isinstance(application, dict):
        raise ServiceEntryError("release application identity is missing")
    source_kind = application.get("source_kind", "git")
    if source_kind == "legacy_broadcast":
        return None
    if source_kind == "git":
        return release
    raise ServiceEntryError("release application source kind is invalid")


def serve(
    vm_root: Path,
    *,
    release_id: str,
    manifest_sha256: str,
    allow_test_root: bool = False,
    candidate_probe_root: Path | None = None,
    candidate_port: int | None = None,
    candidate_release_root: Path | None = None,
) -> None:
    candidate_probe = any(
        value is not None
        for value in (
            candidate_probe_root,
            candidate_port,
            candidate_release_root,
        )
    )
    if candidate_probe and (
        candidate_probe_root is None
        or candidate_port is None
        or candidate_release_root is None
    ):
        raise ServiceEntryError(
            "candidate probe root, port and release root must be supplied together"
        )
    if candidate_probe and not 1024 <= int(candidate_port) <= 65535:
        raise ServiceEntryError("candidate probe port is invalid")
    release, _active, manifest, runtime = resolve_context(
        vm_root,
        expected_release_id=release_id,
        expected_manifest_sha256=manifest_sha256,
        allow_test_root=allow_test_root,
        candidate_probe=candidate_probe,
        candidate_release_root=candidate_release_root,
    )
    required_runtime_fields = {
        "schema_version", "service_name", "base_url", "listen_host", "port",
        "critical_paths", "writer_authority", "write_paths",
        "service_entry_relative_path", "application_source_relative_path",
        "archive_root_relative_path", "var_root_relative_path",
        "migration_root_relative_path", "access_password_digest_path",
        "session_key_path", "comment_database_path", "workspace_database_path",
    }
    if set(runtime) != required_runtime_fields or runtime.get("schema_version") != RUNTIME_SCHEMA:
        raise ServiceEntryError("deployment runtime config schema is not closed")
    if not allow_test_root and (
        runtime.get("base_url") != "http://127.0.0.1:8765"
        or runtime.get("listen_host") != "0.0.0.0"
        or runtime.get("port") != 8765
        or runtime.get("writer_authority") != "D-active"
    ):
        raise ServiceEntryError("production listener/writer topology differs")
    expected_state_paths = {
        "access_password_digest_path": "state/viewer_access_password.digest",
        "session_key_path": "state/viewer_secret.key",
        "comment_database_path": "state/comments.sqlite3",
        "workspace_database_path": "state/research_workspace.sqlite3",
    }
    if any(runtime.get(name) != expected for name, expected in expected_state_paths.items()):
        raise ServiceEntryError("service mutable paths differ from the closed D state layout")
    root = Path(vm_root).resolve(strict=True)
    source = _inside(
        release, runtime["application_source_relative_path"],
        "application source", directory=True,
    )
    entry_relative = runtime["service_entry_relative_path"]
    if not isinstance(entry_relative, str) or Path(entry_relative).is_absolute() or ".." in Path(entry_relative).parts:
        raise ServiceEntryError("service entry tooling path is invalid")
    entry = _regular(root.joinpath(*Path(entry_relative).parts))
    tooling = _regular(root / "tooling", directory=True)
    if not entry.is_relative_to(tooling):
        raise ServiceEntryError("service entry is outside D tooling")
    if Path(__file__).resolve(strict=True) != entry:
        raise ServiceEntryError("service entry is not loaded from fixed D tooling")
    archive = _inside(
        release, runtime["archive_root_relative_path"], "archive root", directory=True
    )
    var_root = _inside(
        release, runtime["var_root_relative_path"], "runtime root", directory=True
    )
    migration = _inside(
        release, runtime["migration_root_relative_path"], "migration root", directory=True
    )
    database_root = _regular(var_root / "db", directory=True)
    if candidate_probe:
        probe = _regular(Path(candidate_probe_root), directory=True)
        expected_probe_parent = _regular(root / "tmp" / "candidate-probes", directory=True)
        if not probe.is_relative_to(expected_probe_parent):
            raise ServiceEntryError("candidate probe root is outside D-root candidate tmp")
        state = _regular(probe / "state", directory=True)
        tmp = _regular(probe / "tmp", directory=True)
    else:
        state = _regular(root / "state", directory=True)
        tmp = _regular(root / "tmp" / "service", directory=True)
    for variable in ("TEMP", "TMP"):
        if Path(os.environ.get(variable, "")).resolve(strict=True) != tmp:
            raise ServiceEntryError(f"{variable} is not the reviewed D-root service temp")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["QUANT_HUB_READ_ONLY_DATABASE_ROOT"] = str(database_root)

    sys.path.insert(0, str(source))

    from quant_hub.app import create_app  # noqa: PLC0415
    from quant_hub.config import Settings  # noqa: PLC0415
    import quant_hub as application_package  # noqa: PLC0415

    tooling_package = _regular(entry.parent.parent, directory=True)
    if str(tooling_package) not in application_package.__path__:
        application_package.__path__.insert(0, str(tooling_package))
    from quant_hub import web as application_web  # noqa: PLC0415

    tooling_web = _regular(tooling_package / "web", directory=True)
    if str(tooling_web) not in application_web.__path__:
        application_web.__path__.insert(0, str(tooling_web))
    from quant_hub.web import access_gate  # noqa: PLC0415

    access_gate_path = _regular(tooling_web / "access_gate.py")
    if _regular(Path(access_gate.__file__)) != access_gate_path:
        raise ServiceEntryError("reviewed D-tooling access gate import identity differs")

    def state_path(key: str) -> Path:
        raw = runtime[key]
        if not isinstance(raw, str):
            raise ServiceEntryError(f"{key} is invalid")
        path = _regular(
            state / Path(raw).name if candidate_probe else root.joinpath(*Path(raw).parts)
        )
        if not path.is_relative_to(state):
            raise ServiceEntryError(f"{key} is outside external state")
        return path

    comment_db = state_path("comment_database_path")
    workspace_db = state_path("workspace_database_path")
    digest_path = state_path("access_password_digest_path")
    session_path_raw = runtime["session_key_path"]
    if not isinstance(session_path_raw, str):
        raise ServiceEntryError("session_key_path is invalid")
    session_path = (
        state / Path(session_path_raw).name
        if candidate_probe
        else root.joinpath(*Path(session_path_raw).parts)
    )
    if not session_path.resolve(strict=False).is_relative_to(state):
        raise ServiceEntryError("session key is outside external state")

    settings = Settings.default(
        project_root=release,
        archive_root=archive,
        var_root=var_root,
        migration_root=migration,
        # Candidate and steady processes both consume immutable release bytes;
        # all mutable state is supplied by the external D state/probe roots.
        read_only_runtime=True,
    )
    application_config: dict[str, object] = {
        "SECRET_KEY": _secret_key(session_path),
        "TRUSTED_ORIGINS": _trusted_origins(
            int(candidate_port) if candidate_probe else int(runtime["port"])
        ),
        "SESSION_COOKIE_SECURE": False,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_NAME": "quant_hub_broadcast_session",
        "COMMENT_DATABASE_PATH": comment_db,
        "RESEARCH_WORKSPACE_DATABASE_PATH": workspace_db,
    }
    direct_asset_root = os.environ.get("QRH_DIRECT_PRESENTATION_ASSET_ROOT")
    if direct_asset_root:
        presentation_assets = _regular(Path(direct_asset_root), directory=True)
        expected_presentation_assets = _regular(
            root / "state" / "archive_presentation_assets", directory=True
        )
        if presentation_assets != expected_presentation_assets:
            raise ServiceEntryError(
                "direct presentation asset root differs from reviewed D state"
            )
        application_config["ARCHIVE_PRESENTATION_ASSET_ROOT"] = presentation_assets
    generic_release_root = _generic_release_root(release, manifest)
    if generic_release_root is not None:
        application_config["GENERIC_RESEARCH_RELEASE_ROOT"] = generic_release_root
    app = create_app(settings, application_config)
    access_gate.install_access_gate(
        app, access_gate.load_password_digest(digest_path)
    )
    snapshot_id = str(manifest["content"]["snapshot_id"])
    writer_authority = (
        "candidate-checkpoint-isolated" if candidate_probe else str(runtime["writer_authority"])
    )
    port = int(candidate_port) if candidate_probe else int(runtime["port"])

    @app.get("/deploymentz")
    def deploymentz():
        from flask import jsonify, request  # noqa: PLC0415

        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify({"status": "not_found"}), 404
        return jsonify(
            {
                "schema_version": "qrh-service-deployment-health/v1",
                "status": "ok",
                "release_id": release_id,
                "manifest_sha256": manifest_sha256,
                "snapshot_id": snapshot_id,
                "writer_authority": writer_authority,
                "pid": os.getpid(),
                "port": port,
            }
        )

    @app.after_request
    def deployment_header(response):
        response.headers.setdefault("X-Quant-Hub-Release", release_id)
        return response

    app.run(
        host="127.0.0.1" if candidate_probe else str(runtime["listen_host"]),
        port=port, debug=False,
        use_reloader=False, threaded=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vm-root", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--test-root", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--candidate-probe-root", type=Path)
    parser.add_argument("--candidate-port", type=int)
    parser.add_argument("--candidate-release-root", type=Path)
    args = parser.parse_args(argv)
    if args.test_root and os.environ.get("QRH_TEST_ONLY_ALLOW_NONPRODUCTION_ROOT") != "1":
        parser.error("--test-root requires the explicit test-only environment marker")
    serve(
        args.vm_root,
        release_id=args.release_id,
        manifest_sha256=args.manifest_sha256,
        allow_test_root=args.test_root,
        candidate_probe_root=args.candidate_probe_root,
        candidate_port=args.candidate_port,
        candidate_release_root=args.candidate_release_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
