"""Installed, cwd-independent CLI for the local stdio MCP consumer."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from quant_hub.knowledge.contracts import canonical_json

from .install import (
    ClientConfig,
    ProfileInstallError,
    install_profile,
    uninstall_profile,
)
from .mirror import (
    FileAuthorityProbe,
    MirrorError,
    MirrorStore,
    OpenSSHAuthoritySource,
)
from .server import serve_stdio
from .service import KnowledgeMCPService


def _client(path: str) -> tuple[ClientConfig, KnowledgeMCPService]:
    config = ClientConfig.load(Path(path))
    store = MirrorStore(config.mirror_root)
    if config.authority_mode == "openssh":
        assert config.ssh_alias is not None
        authority = OpenSSHAuthoritySource(config.ssh_alias)
        artifact_source = authority
    else:
        assert config.authority_active_path is not None
        assert config.authority_release_root is not None
        assert config.artifact_release_root is not None
        authority = FileAuthorityProbe(
            config.authority_active_path, config.authority_release_root
        )
        artifact_source = config.artifact_release_root
    service = KnowledgeMCPService(
        store=store,
        authority=authority,
        artifact_release_root=artifact_source,
    )
    return config, service


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrh-knowledge-mcp")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve-stdio")
    serve.add_argument("--client-config", required=True)
    install = commands.add_parser("install")
    install.add_argument("--scope", choices=("user", "project"), required=True)
    install.add_argument("--profile-root", type=Path, required=True)
    install.add_argument("--data-root", type=Path, required=True)
    install.add_argument("--project-root", type=Path)
    install.add_argument("--mirror-root", type=Path, required=True)
    install.add_argument("--authority-mode", choices=("file", "openssh"), default="file")
    install.add_argument("--authority-active", type=Path)
    install.add_argument("--authority-release-root", type=Path)
    install.add_argument("--artifact-release-root", type=Path)
    install.add_argument("--ssh-alias")
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--client-config", required=True)
    uninstall = commands.add_parser("uninstall")
    uninstall.add_argument("--scope", choices=("user", "project"), required=True)
    uninstall.add_argument("--profile-root", type=Path, required=True)
    uninstall.add_argument("--project-root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    exit_code = 0
    try:
        if arguments.command == "serve-stdio":
            _config, service = _client(arguments.client_config)
            return serve_stdio(service)
        if arguments.command == "install":
            config = (
                ClientConfig(
                    mirror_root=arguments.mirror_root,
                    authority_mode="openssh",
                    ssh_alias=arguments.ssh_alias,
                )
                if arguments.authority_mode == "openssh"
                else ClientConfig(
                    mirror_root=arguments.mirror_root,
                    authority_active_path=arguments.authority_active,
                    authority_release_root=arguments.authority_release_root,
                    artifact_release_root=arguments.artifact_release_root,
                )
            )
            value = install_profile(
                scope=arguments.scope,
                profile_root=arguments.profile_root,
                data_root=arguments.data_root,
                project_root=arguments.project_root,
                client_config=config,
            )
        elif arguments.command == "doctor":
            config, service = _client(arguments.client_config)
            startup = service.startup_probe()
            observation = service.authority.probe()
            local = MirrorStore(config.mirror_root).current()
            fresh = (
                startup["availability"] == "fresh"
                and local is not None
                and local.identity == observation.identity
            )
            value = {
                "schema_version": "qrh-mcp-doctor/v1",
                "status": "fresh" if fresh else "stale",
                "authority_identity": observation.identity.to_dict(),
                "local_identity": local.identity.to_dict() if local else None,
                "authority_verified_at": observation.verified_at,
                "cwd_independent": True,
                "transport": "stdio",
            }
            if not fresh:
                exit_code = 2
        else:
            value = uninstall_profile(
                scope=arguments.scope,
                profile_root=arguments.profile_root,
                project_root=arguments.project_root,
            )
    except (MirrorError, OSError, ProfileInstallError, TypeError, ValueError) as error:
        value = {
            "schema_version": "qrh-mcp-cli-error/v1",
            "status": "error",
            "error_type": type(error).__name__,
            "message": str(error),
        }
        sys.stdout.write(canonical_json(value) + "\n")
        return 2
    sys.stdout.write(canonical_json(value) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
